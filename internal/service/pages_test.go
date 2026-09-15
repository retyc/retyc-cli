package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// keepPage is the process step of tests that only exercise fetching.
func keepPage(_ context.Context, page int) int { return page }

// Pages after the first are fetched concurrently, never more than
// nodeListPageConcurrency at once, and returned in page order whatever order
// they complete in.
func TestFetchAllPages_ConcurrentInOrder(t *testing.T) {
	var inFlight, peak int32
	fetch := func(_ context.Context, page int) (int, int, error) {
		n := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		// Later pages answer first, so an order bug cannot hide.
		time.Sleep(time.Duration(12-page) * time.Millisecond)

		return page, 10, nil
	}

	got, err := fetchAllPages(context.Background(), fetch, keepPage)
	if err != nil {
		t.Fatalf("fetchAllPages: %v", err)
	}
	for i, page := range got {
		if page != i+1 {
			t.Fatalf("results = %v, want pages 1..10 in order", got)
		}
	}
	if len(got) != 10 {
		t.Fatalf("got %d pages, want 10", len(got))
	}
	if peak < 2 || peak > nodeListPageConcurrency {
		t.Errorf("peak concurrency = %d, want between 2 and %d", peak, nodeListPageConcurrency)
	}
}

// The page count is read from every response, not only the first: a folder
// that grows while it is listed gains pages that must still be fetched.
func TestFetchAllPages_FolderGrowsDuringListing(t *testing.T) {
	var mu sync.Mutex
	var fetched []int
	fetch := func(_ context.Context, page int) (int, int, error) {
		mu.Lock()
		fetched = append(fetched, page)
		mu.Unlock()
		if page == 1 {
			return page, 2, nil
		}

		return page, 3, nil
	}

	got, err := fetchAllPages(context.Background(), fetch, keepPage)
	if err != nil {
		t.Fatalf("fetchAllPages: %v", err)
	}
	if fmt.Sprint(got) != "[1 2 3]" {
		t.Errorf("results = %v, want [1 2 3]", got)
	}
	if len(fetched) != 3 {
		t.Errorf("fetched pages %v, want each of 1..3 once", fetched)
	}
}

// A failing page fails the whole listing and cancels the pages still running.
func TestFetchAllPages_ErrorCancelsTheRest(t *testing.T) {
	boom := errors.New("boom")
	fetch := func(ctx context.Context, page int) (int, int, error) {
		switch page {
		case 1:
			return page, 6, nil
		case 2:
			return 0, 0, boom
		default:
			select {
			case <-ctx.Done():
				return 0, 0, ctx.Err()
			case <-time.After(5 * time.Second):
				return page, 6, nil
			}
		}
	}

	start := time.Now()
	if _, err := fetchAllPages(context.Background(), fetch, keepPage); !errors.Is(err, boom) {
		t.Errorf("error = %v, want boom", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the other pages were not cancelled")
	}
}

// Processing (decryption) runs outside the fetch slots: a page being processed
// must neither hold back the other pages, nor delay the pages that follow the
// first one. Here every process step blocks until the last page is fetched,
// which can only happen if processing leaves every slot free.
func TestFetchAllPages_ProcessingHoldsNoSlot(t *testing.T) {
	const pages = nodeListPageConcurrency + 2
	lastFetched := make(chan struct{})
	fetch := func(_ context.Context, page int) (int, int, error) {
		if page == pages {
			close(lastFetched)
		}

		return page, pages, nil
	}
	process := func(_ context.Context, page int) int {
		select {
		case <-lastFetched:
		case <-time.After(2 * time.Second):
			t.Errorf("page %d: processing held a slot, the last page was never fetched", page)
		}

		return page
	}

	got, err := fetchAllPages(context.Background(), fetch, process)
	if err != nil {
		t.Fatalf("fetchAllPages: %v", err)
	}
	if len(got) != pages {
		t.Errorf("got %d pages, want %d", len(got), pages)
	}
}

// End to end: a 250-node folder is listed with the API's maximum page size,
// in order, with every name decrypted.
func TestListNodesByIDWithSession_Paginated(t *testing.T) {
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sessKey.Recipient().String()
	const total = 250
	items := make([]api.DataroomNodeItem, total)
	for i := range items {
		items[i] = api.DataroomNodeItem{Node: api.DataroomNode{
			ID: fmt.Sprintf("n%03d", i), NameEnc: encName(t, fmt.Sprintf("file-%03d", i), pub),
		}}
	}

	var sizes sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		sizes.Store(size, true)
		if size <= 0 || page <= 0 {
			http.Error(w, "bad page", http.StatusBadRequest)

			return
		}
		start, end := (page-1)*size, page*size
		start, end = min(start, total), min(end, total)
		_ = json.NewEncoder(w).Encode(api.DataroomNodePage{
			Items: items[start:end], Total: total, Page: page, Pages: (total + size - 1) / size,
		})
	}))
	defer srv.Close()
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)

	nodes, err := ListNodesByIDWithSession(context.Background(), client, "dr1", nil,
		&DataroomSession{Identity: sessKey, PublicKey: pub})
	if err != nil {
		t.Fatalf("ListNodesByIDWithSession: %v", err)
	}
	if len(nodes) != total {
		t.Fatalf("got %d nodes, want %d", len(nodes), total)
	}
	for i, n := range nodes {
		if want := fmt.Sprintf("file-%03d", i); n.Name != want || n.ID != fmt.Sprintf("n%03d", i) {
			t.Fatalf("nodes[%d] = %s/%s, want n%03d/%s", i, n.ID, n.Name, i, want)
		}
	}
	sizes.Range(func(k, _ any) bool {
		if k.(int) != nodeListPageSize {
			t.Errorf("requested page size %d, want %d", k, nodeListPageSize)
		}

		return true
	})
}
