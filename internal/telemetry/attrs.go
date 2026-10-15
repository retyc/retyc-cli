package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Attribute keys shared by the instrumentation sites. Values must never carry
// a file or folder name, a dataroom title, a command argument, a header, a
// body or an error message: the CLI exists to keep those encrypted.
const (
	AttrCommand    = attribute.Key("retyc.command")
	AttrCLIVersion = attribute.Key("retyc.cli.version")
	AttrPathParams = attribute.Key("retyc.path.params")
	AttrDataroomID = attribute.Key("retyc.dataroom.id")
	AttrNodeID     = attribute.Key("retyc.node.id")
	AttrChunkIndex = attribute.Key("retyc.chunk.index")
	// Identifiers of the other API resources, keyed by the route segment
	// before them (see resourceKeys in roundtripper.go).
	AttrVersionID         = attribute.Key("retyc.version.id")
	AttrTransferID        = attribute.Key("retyc.transfer.id") // the backend says "share"
	AttrFileID            = attribute.Key("retyc.file.id")
	AttrMemberID          = attribute.Key("retyc.member.id")
	AttrUserID            = attribute.Key("retyc.user.id")
	AttrBlacklistDomainID = attribute.Key("retyc.blacklist_domain.id")
	// Chunk sizes differ by direction: the encrypt span sees the plaintext,
	// the decrypt span the ciphertext (AGE header + payload).
	AttrChunkPlaintextBytes  = attribute.Key("retyc.chunk.plaintext_bytes")
	AttrChunkCiphertextBytes = attribute.Key("retyc.chunk.ciphertext_bytes")
	AttrKeyKind              = attribute.Key("retyc.key.kind")   // user | transfer
	AttrKeySource            = attribute.Key("retyc.key.source") // passphrase | keyring
	AttrCacheName            = attribute.Key("retyc.cache.name")
	AttrCacheHit             = attribute.Key("retyc.cache.hit")
	// AttrCacheStale marks a hit on an expired entry, served while a
	// background refresh replaces it.
	AttrCacheStale = attribute.Key("retyc.cache.stale")
	AttrNodeCount  = attribute.Key("retyc.node.count")
	AttrPathDepth  = attribute.Key("retyc.path.depth")
	AttrMCPTool    = attribute.Key("retyc.mcp.tool")
	// AttrFuseOp is the FUSE operation of a "FUSE <op>" span (lookup, readdir,
	// open, read, statfs): a fixed vocabulary, never a name or a path.
	AttrFuseOp = attribute.Key("retyc.fuse.op")
	// AttrUnsafeWrite is the unsafe_write parameter of an upload: true when the
	// API answers before storing the chunk (see unsafeWriteAttribute).
	AttrUnsafeWrite = attribute.Key("retyc.upload.unsafe_write")
	AttrErrorType   = attribute.Key("error.type")
	// AttrDBSystem and AttrDBOperation describe a "redis <op>" span of the
	// shared metadata store: the system ("redis") and the store's own name for
	// the operation (get_node, put_listing, ...), never a command, a key, a
	// field or a value.
	AttrDBSystem    = attribute.Key("db.system.name")
	AttrDBOperation = attribute.Key("db.operation.name")
	// AttrRetryAttempt and AttrRetryWaitMS describe the wait of a request held
	// back by the API rate limit (see ThrottleEvent).
	AttrRetryAttempt = attribute.Key("retyc.retry.attempt")
	AttrRetryWaitMS  = attribute.Key("retyc.retry.wait_ms")
)

// EventThrottle is the event of a request waiting for the API rate limit.
const EventThrottle = "api.throttle"

// ThrottleEvent records, on the span of ctx, that an API request is held back
// by the rate limit: attempt is the number of times it was already sent (0
// for a request waiting behind the refusal of another one), wait the pause
// ahead. Each attempt is a CLIENT span of its own; the wait between them
// belongs to the span that made the call.
func ThrottleEvent(ctx context.Context, attempt int, wait time.Duration) {
	trace.SpanFromContext(ctx).AddEvent(EventThrottle, trace.WithAttributes(
		AttrRetryAttempt.Int(attempt),
		AttrRetryWaitMS.Int64(wait.Milliseconds()),
	))
}

// ErrorType returns the Go type of the innermost error under the fmt.Errorf
// wrappers, without the pointer marker, e.g. "fs.PathError" or "net.OpError".
// It is the only thing about an error that a span records: messages
// routinely embed paths and file names.
func ErrorType(err error) string {
	for {
		t := strings.TrimPrefix(fmt.Sprintf("%T", err), "*")
		if t != "fmt.wrapError" && t != "fmt.wrapErrors" {
			return t
		}
		inner := errors.Unwrap(err)
		if inner == nil {
			return t
		}
		err = inner
	}
}

// RecordError marks span as failed with the error type only.
func RecordError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.SetStatus(codes.Error, "")
	span.SetAttributes(AttrErrorType.String(ErrorType(err)))
}
