package service

import (
	"sync/atomic"

	"github.com/retyc/retyc-cli/internal/config"
)

// defaultConcurrency applies until SetConcurrency is called: in tests, and for
// any caller that never loads the configuration.
var defaultConcurrency = config.ConcurrencyConfig{
	List:     config.DefaultConcurrency,
	Upload:   config.DefaultConcurrency,
	Download: config.DefaultConcurrency,
}

var concurrency atomic.Pointer[config.ConcurrencyConfig]

// SetConcurrency sets the process-wide bounds on concurrent API requests
// (api.concurrency.*): listing pages, upload chunks and download chunks. The
// root command applies the loaded configuration before any command runs.
//
// config.Load already rejects values outside 1..config.MaxConcurrency; they are
// clamped to that range here all the same, since a zero bound would leave the
// workers without a single slot and an unbounded one sizes channels and
// in-flight work directly.
func SetConcurrency(c config.ConcurrencyConfig) {
	c.List = clampConcurrency(c.List)
	c.Upload = clampConcurrency(c.Upload)
	c.Download = clampConcurrency(c.Download)
	concurrency.Store(&c)
}

// clampConcurrency brings v into 1..config.MaxConcurrency.
func clampConcurrency(v int) int {
	return min(max(v, 1), config.MaxConcurrency)
}

// Concurrency returns the bounds set by SetConcurrency, or the defaults.
func Concurrency() config.ConcurrencyConfig {
	if c := concurrency.Load(); c != nil {
		return *c
	}

	return defaultConcurrency
}
