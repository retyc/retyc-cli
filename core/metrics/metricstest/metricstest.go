// Package metricstest records the observations of core/metrics in memory, for
// the tests of the core: they read a point's value without depending on a
// metrics library. Standard library only.
package metricstest

import (
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/retyc/retyc-cli/core/metrics"
)

var once sync.Once

// Install replaces every measurement point of core/metrics with an in-memory
// one. It is idempotent; call it from the init() of a test package, before
// any observation.
func Install() {
	once.Do(func() {
		metrics.Install(metrics.Set{
			Ops:                   newVec(),
			OpDuration:            newHistVec(),
			Bytes:                 newVec(),
			OpenHandles:           newGaugeVec(),
			BackgroundDeletes:     newVec(),
			CacheLookups:          newVec(),
			DataroomListRefreshes: newVec(),
			WarmupFolders:         newVec(),
			WarmupDuration:        &Value{},
			SpoolBytes:            &Value{},
			Uploads:               newVec(),
			LocksHeld:             &Value{},
			StoreOpDuration:       newHistVec(),
			APIRequests:           newVec(),
			APIRequestDuration:    newHistVec(),
			APIThrottleEpisodes:   &Value{},
			APIRateLimited:        newVec(),
			TokenRefreshes:        newVec(),
			TokenExpiry:           &Value{},
		})
	})
}

// Get returns the value of a counter or a gauge, or the number of samples of
// a histogram, as recorded since Install; 0 for a point Install did not
// replace.
func Get(point any) float64 {
	if v, ok := point.(*Value); ok {
		return v.Get()
	}

	return 0
}

// Value is a counter, a gauge, or the sample count of a histogram.
type Value struct{ bits atomic.Uint64 }

// Get returns the current value.
func (v *Value) Get() float64 { return math.Float64frombits(v.bits.Load()) }

// Add adds d.
func (v *Value) Add(d float64) {
	for {
		old := v.bits.Load()
		if v.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// Set sets the value.
func (v *Value) Set(x float64) { v.bits.Store(math.Float64bits(x)) }

// Inc adds 1.
func (v *Value) Inc() { v.Add(1) }

// Dec subtracts 1.
func (v *Value) Dec() { v.Add(-1) }

// Observe counts a sample.
func (v *Value) Observe(float64) { v.Add(1) }

// family holds one Value per set of label values.
type family struct{ m sync.Map }

func (f *family) get(lvs []string) *Value {
	v, _ := f.m.LoadOrStore(strings.Join(lvs, "\x00"), &Value{})

	return v.(*Value) //nolint:forcetypeassert // only *Value is stored
}

type counterVec struct{ family }

func newVec() *counterVec { return &counterVec{} }

func (c *counterVec) WithLabelValues(lvs ...string) metrics.Counter { return c.get(lvs) }

type gaugeVec struct{ family }

func newGaugeVec() *gaugeVec { return &gaugeVec{} }

func (g *gaugeVec) WithLabelValues(lvs ...string) metrics.Gauge { return g.get(lvs) }

type histVec struct{ family }

func newHistVec() *histVec { return &histVec{} }

func (h *histVec) WithLabelValues(lvs ...string) metrics.Observer { return h.get(lvs) }
