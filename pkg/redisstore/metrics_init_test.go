package redisstore

import "github.com/retyc/retyc-cli/pkg/prommetrics"

// The tests read the Prometheus collectors, as the CLI installs them.
func init() { prommetrics.Install() }
