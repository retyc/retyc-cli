package service

import (
	"context"
	"slices"
	"sync"
)

// nodeListPageSize is the largest page GET /dataroom/{id}/nodes accepts.
// Every page is a round trip, so a listing costs as few pages as the API allows.
const nodeListPageSize = 100

// nodeListPageConcurrency bounds the pages fetched at once after the first.
const nodeListPageConcurrency = 4

// fetchAllPages returns every page of a paginated listing, fetched then
// processed, in page order.
//
// fetch performs one page's round trip and returns its raw result with the page
// count the API reported. The count is unknown until the first page answers, so
// page 1 is fetched alone, then the remaining pages concurrently,
// nodeListPageConcurrency at a time. A folder that grows while it is listed
// reports a larger count on a later page: those extra pages are fetched in a
// further round, as the sequential loop did by re-reading the count on every
// page.
//
// process turns a raw page into its result (decrypting names). It runs in its
// own goroutine as soon as the page has arrived, outside the fetch slots: a
// slot bounds concurrent round trips only, so decrypting a page never delays
// the next page's request — not even page 1's decryption, which runs while
// the other pages are being requested.
//
// The first fetch error cancels the pages still running and is returned, once
// the processing already started has finished.
func fetchAllPages[R, T any](
	ctx context.Context,
	fetch func(ctx context.Context, page int) (R, int, error),
	process func(ctx context.Context, raw R) T,
) ([]T, error) {
	first, pages, err := fetch(ctx, 1)
	if err != nil {
		return nil, err
	}

	var processing sync.WaitGroup
	firstRound := make([]T, 1)
	rounds := [][]T{firstRound}
	processing.Add(1)
	go func() {
		defer processing.Done()
		firstRound[0] = process(ctx, first)
	}()

	for next := 2; next <= pages; {
		round, reported, err := fetchPageRange(ctx, next, pages, fetch, process, &processing)
		if err != nil {
			processing.Wait()

			return nil, err
		}
		rounds = append(rounds, round)
		next = pages + 1
		pages = max(pages, reported)
	}
	processing.Wait()

	return slices.Concat(rounds...), nil
}

// fetchPageRange fetches pages from..to concurrently, nodeListPageConcurrency
// round trips at a time, and returns the slice their processed results are
// written into, in page order, with the largest page count any of them
// reported. Each page is handed to process in a goroutine tracked by
// processing, so the slice is complete only once processing is done.
func fetchPageRange[R, T any](
	ctx context.Context, from, to int,
	fetch func(ctx context.Context, page int) (R, int, error),
	process func(ctx context.Context, raw R) T,
	processing *sync.WaitGroup,
) ([]T, int, error) {
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]T, to-from+1)
	var (
		fetching sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		reported int
	)
	slots := make(chan struct{}, nodeListPageConcurrency)
	for page := from; page <= to; page++ {
		select {
		case slots <- struct{}{}:
		case <-fetchCtx.Done():
		}
		if fetchCtx.Err() != nil {
			break
		}
		fetching.Add(1)
		go func() {
			defer fetching.Done()
			raw, count, err := fetch(fetchCtx, page)
			<-slots // the round trip is over: free the slot before processing
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancel()
				}

				return
			}
			if firstErr != nil {
				return // the listing already failed: skip the wasted work
			}
			reported = max(reported, count)
			processing.Add(1)
			go func() {
				defer processing.Done()
				results[page-from] = process(ctx, raw)
			}()
		}()
	}
	fetching.Wait()

	if firstErr != nil {
		return nil, 0, firstErr
	}
	// The parent context was cancelled before every page was started.
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	return results, reported, nil
}
