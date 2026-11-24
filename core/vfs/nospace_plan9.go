package vfs

// isNoSpace is always false on Plan 9, whose errors are strings without a
// portable "no space" value: a full spool reads as a plain I/O error.
func isNoSpace(error) bool { return false }
