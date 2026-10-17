package api

import "errors"

// ErrorCodeHeader is the response header in which the dataroom API puts the
// stable code of a refusal (UPPER_SNAKE_CASE, one status per code). The
// detail of such a refusal is a message for humans, free to change: branch on
// the code. A refusal without the header did not come from the dataroom code
// (request validation, authentication, an unknown route, a proxy) or comes
// from an API that predates the codes; callers then fall back on the status,
// and on the former detail texts where they had to read one.
const ErrorCodeHeader = "X-Error-Code"

// The codes of the dataroom API this client branches on. The API has more
// (its OpenAPI lists them per route); ErrorCode returns any of them.
const (
	CodeDataroomNotFound        = "DATAROOM_NOT_FOUND"
	CodeNodeNotFound            = "NODE_NOT_FOUND"
	CodeParentNotFound          = "PARENT_NOT_FOUND"
	CodeVersionNotFound         = "VERSION_NOT_FOUND"
	CodeChunkNotFound           = "CHUNK_NOT_FOUND"
	CodeNodeDeleted             = "NODE_DELETED"
	CodeParentDeleted           = "PARENT_DELETED"
	CodeVersionDeleted          = "VERSION_DELETED"
	CodeNameHolderDeleted       = "NAME_HOLDER_DELETED"
	CodeNotAMember              = "NOT_A_MEMBER"
	CodeRoleForbidden           = "ROLE_FORBIDDEN"
	CodeDataroomReadOnly        = "DATAROOM_READ_ONLY"
	CodeNotVersionAuthor        = "NOT_VERSION_AUTHOR"
	CodeReplaceForbidden        = "REPLACE_FORBIDDEN"
	CodeStorageExceeded         = "STORAGE_EXCEEDED"
	CodeStoragePlanExceeded     = "STORAGE_PLAN_EXCEEDED"
	CodeStorageCapacityTooSmall = "STORAGE_CAPACITY_TOO_SMALL"
	CodeStorageCapacityShrink   = "STORAGE_CAPACITY_SHRINK"
	CodeVersionsLimit           = "VERSIONS_LIMIT"
	CodeMimeTypesLimit          = "MIME_TYPES_LIMIT"
	CodeSingleUploadTooLarge    = "SINGLE_UPLOAD_TOO_LARGE"
	CodeNameTaken               = "NAME_TAKEN"
	CodeReplaceTargetIsFolder   = "REPLACE_TARGET_IS_FOLDER"
	CodeConcurrentUpdate        = "CONCURRENT_UPDATE"
	CodeLockConflict            = "LOCK_CONFLICT"
	CodeMimeTypeUnknown         = "MIME_TYPE_UNKNOWN"
	// CodeMasterKeyMismatch: the organization key announced at dataroom
	// creation (master_public_key) is no longer the organization's key.
	CodeMasterKeyMismatch = "MASTER_KEY_MISMATCH"
)

// ErrorCode returns the X-Error-Code of the HTTPError in err's chain, or ""
// when err is not an API refusal or the refusal carries no code.
func ErrorCode(err error) string {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Code
	}

	return ""
}
