package api

import "github.com/retyc/retyc-cli/core/metrics/metricstest"

// The tests read the measurement points from memory (metricstest).
func init() { metricstest.Install() }
