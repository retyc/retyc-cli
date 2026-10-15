// Package retycfs presents datarooms as a FUSE filesystem. It is a thin
// adapter between go-fuse and internal/vfs, which holds the caches, the path
// resolution and the positioned reads; the WebDAV server is the other front
// end of that layer.
//
// Linux only: every other file of the package carries the linux build tag, so
// that the package is empty elsewhere and the module still builds.
//
// This step is read only. The filesystem is mounted "ro", which makes the
// kernel refuse most writes itself; the handlers that could still be reached
// answer EROFS.
//
// Dependency rule: the package imports internal/vfs and go-fuse. It imports
// internal/api and internal/auth for their error sentinels only (errno.go),
// and never internal/service.
package retycfs
