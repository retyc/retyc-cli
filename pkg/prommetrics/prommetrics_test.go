package prommetrics

import (
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// fqNamePattern pulls the metric name out of a Desc's String().
var fqNamePattern = regexp.MustCompile(`fqName: "([^"]+)"`)

func TestAll_OnePrefix(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		ch := make(chan *prometheus.Desc, 4)
		go func() { c.Describe(ch); close(ch) }()
		for d := range ch {
			m := fqNamePattern.FindStringSubmatch(d.String())
			if m == nil {
				t.Fatalf("no fqName in %s", d)
			}
			if !strings.HasPrefix(m[1], "retycfs_") {
				t.Errorf("%s: want the retycfs_ prefix", m[1])
			}
			if seen[m[1]] {
				t.Errorf("%s declared twice", m[1])
			}
			seen[m[1]] = true
		}
	}
	if len(seen) != len(all) {
		t.Errorf("%d names for %d collectors", len(seen), len(all))
	}
}
