package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server integration",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local MCP server (stdio transport)",
	Long: `Start a local MCP server that exposes all retyc operations as MCP tools.

The server communicates over stdin/stdout using the MCP protocol.
Authentication uses the same stored token as the CLI.

Key passphrase: set RETYC_KEY_PASSPHRASE (env var).
Transfer passphrase: provide via tool arguments.

Example configuration for Claude Desktop (claude_desktop_config.json):
  {
    "mcpServers": {
      "retyc": {
        "command": "retyc",
        "args": ["mcp", "serve"],
        "env": { "RETYC_KEY_PASSPHRASE": "your-passphrase" }
      }
    }
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv := server.NewMCPServer(
			"retyc",
			Version,
			server.WithToolCapabilities(false),
			server.WithDescription(
				"RETYC end-to-end encrypted file transfer and dataroom management. "+
					"Runs as a local process: reads and encrypts files in-process (post-quantum AGE MLKEM768-X25519) "+
					"before any byte leaves the machine.",
			),
			server.WithInstructions(buildMCPInstructions()),
		)

		registerMCPTools(srv)

		return server.ServeStdio(srv)
	},
}

// isWSL reports whether the current process runs inside Windows Subsystem for Linux.
func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(b))

	return strings.Contains(lower, "microsoft")
}

// buildMCPInstructions generates server instructions injected into the LLM system prompt.
// Content is resolved at startup so the model always knows the runtime OS and path format.
func buildMCPInstructions() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	homeDir, _ := os.UserHomeDir()

	var pathRules string
	switch goos {
	case "windows":
		pathRules = "Absolute Windows paths only (e.g. C:\\Users\\Alice\\Downloads\\file.pdf). Use backslashes."
	default:
		if isWSL() {
			pathRules = "Running inside WSL. Use POSIX paths for Linux files (/home/...) " +
				"and /mnt/c/Users/<WindowsUser>/... to reach Windows files."
		} else {
			pathRules = "Absolute POSIX paths only (e.g. /home/alice/Downloads/file.pdf)."
		}
	}

	return fmt.Sprintf(`## Runtime environment
OS: %s/%s
User home: %s

## File paths
%s
All file-path parameters are resolved by this server process on the local filesystem — not by you.

## Shell access — STRICTLY FORBIDDEN
You have NO shell, terminal, or filesystem-browsing capability through this server.
NEVER call bash, cmd, powershell, ls, dir, find, stat, or any tool from another MCP server to locate or inspect files.
If the user did not provide an absolute path: ASK them for it. Do not guess or enumerate.

## Zero-knowledge rule
NEVER read, open, preview, hash, or summarize file contents.
NEVER route file data through any other tool, MCP server, or API.
You handle paths, names, sizes, and IDs only — the server handles all crypto and I/O.

## Workflow
1. Call auth_status first if you are unsure whether the user is authenticated.
   If authenticated=false: call auth_login_start immediately — do NOT tell the user to run any CLI command.
2. If any tool returns error_code=not_authenticated: call auth_login_start immediately.
3. To upload: pass the user-provided absolute path(s) directly to transfer_send or dataroom_upload.
4. To download: pass the user-provided absolute destination directory to transfer_download or dataroom_download.
5. Never read or relay written files after download unless the user explicitly requests it.`,
		goos, goarch, homeDir, pathRules,
	)
}

// mcpPassphraseReader returns a PassphraseReader for MCP mode that reads from
// RETYC_KEY_PASSPHRASE only (no interactive terminal prompt is possible in MCP mode).
func mcpPassphraseReader() (string, error) {
	v := os.Getenv("RETYC_KEY_PASSPHRASE")
	if v == "" {
		return "", fmt.Errorf("RETYC_KEY_PASSPHRASE environment variable is required in MCP mode")
	}

	return v, nil
}

// mcpProgressFn returns a ProgressFn that sends MCP progress notifications.
// If progressToken is nil, returns nil (no notifications).
// done is updated atomically because UploadChunks calls progress from concurrent goroutines.
func mcpProgressFn(srv *server.MCPServer, ctx context.Context, progressToken mcp.ProgressToken) service.ProgressFn {
	if progressToken == nil {
		return nil
	}
	var done atomic.Int64

	return func(filename string, chunkBytes int, totalSize int64) {
		newDone := done.Add(int64(chunkBytes))
		_ = srv.SendNotificationToClient(ctx, "notifications/progress", map[string]any{
			"progressToken": progressToken,
			"progress":      newDone,
			"total":         totalSize,
		})
	}
}

// mcpToolError is the structured error format returned by all MCP tools.
type mcpToolError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

// toJSON marshals v to a JSON string for use in tool results.
func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		fallback, fallbackErr := json.Marshal(map[string]string{
			"error": "marshal failed: " + err.Error(),
		})
		if fallbackErr != nil {
			return `{"error":"marshal failed"}`
		}

		return string(fallback)
	}

	return string(b)
}

// toolErr returns a structured JSON error result so agents can pattern-match on error_code.
func toolErr(err error) (*mcp.CallToolResult, error) {
	code := "error"
	switch {
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		return mcp.NewToolResultText(toJSON(map[string]any{
			"error_code": "not_authenticated",
			"message":    err.Error(),
			"next_step":  "Call auth_login_start now. Do NOT suggest running any CLI command.",
		})), nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code = "cancelled"
	}

	return mcp.NewToolResultText(toJSON(mcpToolError{ErrorCode: code, Message: err.Error()})), nil
}

// registerMCPTools registers all 20 MCP tools on the server.
func registerMCPTools(srv *server.MCPServer) {
	registerAuthTools(srv)
	registerUserTools(srv)
	registerTransferTools(srv)
	registerDataroomTools(srv)
}

// — Auth tools ————————————————————————————————————————————————————————————————

func registerAuthTools(srv *server.MCPServer) {
	srv.AddTool(
		mcp.NewTool("auth_status",
			mcp.WithDescription(
				"Check authentication status and token validity. "+
					"If the result is authenticated=false, do NOT tell the user to run any CLI command — "+
					"call auth_login_start immediately to initiate the login flow directly from this MCP server.",
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, err := config.Load()
			if err != nil {
				return toolErr(fmt.Errorf("loading config: %w", err))
			}
			tok, err := mustGetToken(ctx, cfg)
			if err != nil {
				return mcp.NewToolResultText(toJSON(map[string]any{
					"authenticated": false,
					"error":         err.Error(),
					"next_step":     "Call auth_login_start now. Do NOT suggest running any CLI command.",
				})), nil
			}
			t, err := tok.Token()
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]any{
				"authenticated": true,
				"expires_at":    t.Expiry.UTC().Format(time.RFC3339),
			})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("auth_login_start",
			mcp.WithDescription(
				"Initiate OIDC device flow login. Returns a URL to open in the browser and a "+
					"device_code to pass to auth_login_poll. Show the verification_uri_complete link to the user.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, err := config.Load()
			if err != nil {
				return toolErr(fmt.Errorf("loading config: %w", err))
			}
			result, err := service.LoginStart(ctx, cfg.API.BaseURL, newHTTPClient(insecure, debug))
			if err != nil {
				return toolErr(err)
			}
			if result.AlreadyAuthenticated {
				return mcp.NewToolResultText(toJSON(map[string]any{
					"already_authenticated": true,
					"expires_at":            result.ExpiresAt.UTC().Format(time.RFC3339),
				})), nil
			}

			return mcp.NewToolResultText(toJSON(map[string]any{
				"verification_uri_complete": result.VerificationURIComplete,
				"verification_uri":          result.VerificationURI,
				"user_code":                 result.UserCode,
				"device_code":               result.DeviceCode,
				"interval":                  result.Interval,
				"expires_in":                result.ExpiresIn,
			})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("auth_login_poll",
			mcp.WithDescription(
				"Poll for the result of a device flow started with auth_login_start. "+
					"Call repeatedly, waiting interval seconds between calls, until done is true. "+
					"When status is \"slow_down\", add extra_delay_seconds to your current interval "+
					"and keep the increased interval for all subsequent calls.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("device_code", mcp.Required(), mcp.Description("device_code returned by auth_login_start")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			deviceCode := req.GetString("device_code", "")
			if deviceCode == "" {
				return toolErr(fmt.Errorf("device_code is required"))
			}
			cfg, err := config.Load()
			if err != nil {
				return toolErr(fmt.Errorf("loading config: %w", err))
			}
			result, err := service.LoginPoll(ctx, cfg.API.BaseURL, deviceCode, newHTTPClient(insecure, debug))
			if err != nil {
				return toolErr(err)
			}
			switch result.Status {
			case service.PollDone:
				return mcp.NewToolResultText(toJSON(map[string]any{
					"done":       true,
					"expires_at": result.ExpiresAt.UTC().Format(time.RFC3339),
				})), nil
			case service.PollSlowDown:
				return mcp.NewToolResultText(toJSON(map[string]any{
					"done": false, "status": service.PollSlowDown, "extra_delay_seconds": result.ExtraDelaySecs,
				})), nil
			default:
				return mcp.NewToolResultText(toJSON(map[string]any{
					"done": false, "status": result.Status,
				})), nil
			}
		},
	)

	srv.AddTool(
		mcp.NewTool("auth_logout",
			mcp.WithDescription("Revoke the server-side session and delete stored credentials"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, err := config.Load()
			if err != nil {
				return toolErr(fmt.Errorf("loading config: %w", err))
			}
			warnings, err := service.Logout(ctx, cfg.API.BaseURL, newHTTPClient(insecure, debug))
			if err != nil {
				return toolErr(err)
			}
			warnStrs := make([]string, len(warnings))
			for i, w := range warnings {
				warnStrs[i] = w.Error()
			}

			return mcp.NewToolResultText(toJSON(map[string]any{
				"ok":       true,
				"warnings": warnStrs,
			})), nil
		},
	)
}

// — User tools ————————————————————————————————————————————————————————————————

func registerUserTools(srv *server.MCPServer) {
	srv.AddTool(
		mcp.NewTool("system_info",
			mcp.WithDescription(
				"Return the runtime OS, architecture, and home directory of the MCP server process. "+
					"home_dir is the home of the OS user running this process (normally the logged-in user). "+
					"IMPORTANT: this server process has FULL access to the local filesystem — it reads and writes files directly. "+
					"Call this whenever the user refers to a file by a relative location "+
					"(e.g. 'on the desktop', 'in Downloads', 'sur le bureau') to get home_dir and path format. "+
					"Then ask the user for the exact folder name if needed (Desktop folder name varies by OS locale). "+
					"NEVER tell the user you cannot access the filesystem.",
			),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			homeDir, _ := os.UserHomeDir()
			var pathFormat string
			switch runtime.GOOS {
			case "windows":
				pathFormat = `absolute Windows path, e.g. C:\Users\Alice\Downloads\file.pdf`
			default:
				pathFormat = "absolute POSIX path, e.g. /home/alice/Downloads/file.pdf"
				if isWSL() {
					pathFormat += "; use /mnt/c/... to reach Windows files"
				}
			}

			return mcp.NewToolResultText(toJSON(map[string]any{
				"os":          runtime.GOOS,
				"arch":        runtime.GOARCH,
				"home_dir":    homeDir,
				"path_format": pathFormat,
			})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("user_info",
			mcp.WithDescription("Get current user profile (email, role, plan, public key)"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			u, err := client.GetMe(ctx)
			if err != nil {
				return toolErr(fmt.Errorf("fetching user info: %w", err))
			}

			return mcp.NewToolResultText(toJSON(u)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("user_quota",
			mcp.WithDescription("Get current user storage and transfer quotas"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			q, err := client.GetQuota(ctx)
			if err != nil {
				return toolErr(fmt.Errorf("fetching quota: %w", err))
			}

			return mcp.NewToolResultText(toJSON(q)), nil
		},
	)
}

// — Transfer tools ————————————————————————————————————————————————————————————

func registerTransferTools(srv *server.MCPServer) {
	var absPathHint string
	if runtime.GOOS == "windows" {
		absPathHint = " (absolute Windows path, e.g. C:\\Users\\Public\\Downloads)"
	} else {
		absPathHint = " (absolute POSIX path; if this server runs in WSL, use /mnt/c/... instead of C:\\...)"
	}

	srv.AddTool(
		mcp.NewTool("transfer_list",
			mcp.WithDescription("List transfers (sent or received)"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("filter",
				mcp.Description("Filter: \"sent\" (default) or \"received\""),
				mcp.DefaultString("sent"),
			),
			mcp.WithNumber("page",
				mcp.Description("Page number (default 1)"),
				mcp.DefaultNumber(1),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			filter := req.GetString("filter", "sent")
			page := req.GetInt("page", 1)

			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.ListTransfers(ctx, client, filter, page)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("transfer_info",
			mcp.WithDescription("Get full details of a transfer including decrypted file names and message"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("id", mcp.Required(), mcp.Description("Transfer ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id := req.GetString("id", "")
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.GetTransferInfo(ctx, cfg, client, id, mcpPassphraseReader)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("transfer_send",
			mcp.WithDescription(
				"Create and upload a new E2EE transfer. "+
					"This server process has FULL access to the local filesystem: it reads, encrypts (post-quantum AGE), "+
					"and uploads each file — plaintext never leaves the machine. "+
					"If the user gives a relative location ('bureau', 'desktop', 'downloads'), "+
					"call system_info to get home_dir, then ask for the exact folder name. "+
					"Pass absolute local paths only; do not read or preview file contents beforehand.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithArray("files",
				mcp.Required(),
				mcp.Description("Array of absolute local file paths to upload"+absPathHint),
				mcp.Items(map[string]any{"type": "string"}),
			),
			mcp.WithString("title", mcp.Description("Transfer title")),
			mcp.WithString("message", mcp.Description("Optional encrypted message for recipients")),
			mcp.WithString("passphrase", mcp.Description("Transfer passphrase (required when recipients have no key)")),
			mcp.WithBoolean("generate_passphrase",
				mcp.Description("Auto-generate a secure random passphrase (returned in result)"),
			),
			mcp.WithArray("to",
				mcp.Description("Recipient email addresses"),
				mcp.Items(map[string]any{"type": "string"}),
			),
			mcp.WithNumber("expire", mcp.Description("Expiration in seconds (default 3600, 0 = no expiration)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var token mcp.ProgressToken
			if req.Params.Meta != nil {
				token = req.Params.Meta.ProgressToken
			}
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.SendTransfer(ctx, cfg, client, service.SendTransferParams{
				FilePaths:          req.GetStringSlice("files", nil),
				Title:              req.GetString("title", ""),
				Message:            req.GetString("message", ""),
				Passphrase:         req.GetString("passphrase", ""),
				GeneratePassphrase: req.GetBool("generate_passphrase", false),
				ToEmails:           req.GetStringSlice("to", nil),
				ExpireSecs:         req.GetInt("expire", 3600),
			}, mcpPassphraseReader, mcpProgressFn(srv, ctx, token))
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("transfer_download",
			mcp.WithDescription(
				"Download and decrypt all files from a transfer to a local directory. "+
					"Decryption happens in-process (post-quantum AGE); only metadata (filenames, sizes, paths) is returned — "+
					"do not read or relay the written files unless the user explicitly requests it.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("id", mcp.Required(), mcp.Description("Transfer ID")),
			mcp.WithString("output_dir", mcp.Required(), mcp.Description("Local destination directory"+absPathHint)),
			mcp.WithString("passphrase",
				mcp.Description("Transfer passphrase (only needed when you have no user key for this transfer)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var token mcp.ProgressToken
			if req.Params.Meta != nil {
				token = req.Params.Meta.ProgressToken
			}
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			outputDir := req.GetString("output_dir", "")
			if outputDir == "" {
				return toolErr(fmt.Errorf("output_dir is required"))
			}
			result, err := service.DownloadTransfer(ctx, cfg, client, service.DownloadTransferParams{
				ShareID:    req.GetString("id", ""),
				OutputDir:  outputDir,
				Passphrase: req.GetString("passphrase", ""),
			}, mcpPassphraseReader, mcpProgressFn(srv, ctx, token))
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("transfer_disable",
			mcp.WithDescription("Disable a transfer"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("id", mcp.Required(), mcp.Description("Transfer ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			if err := service.DisableTransfer(ctx, client, req.GetString("id", "")); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("transfer_enable",
			mcp.WithDescription("Re-enable a previously disabled transfer"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("id", mcp.Required(), mcp.Description("Transfer ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			if err := service.EnableTransfer(ctx, client, req.GetString("id", "")); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)
}

// — Dataroom tools ————————————————————————————————————————————————————————————

func registerDataroomTools(srv *server.MCPServer) {
	var absPathHint string
	if runtime.GOOS == "windows" {
		absPathHint = " (absolute Windows path, e.g. C:\\Users\\Public\\Downloads)"
	} else {
		absPathHint = " (absolute POSIX path; if this server runs in WSL, use /mnt/c/... instead of C:\\...)"
	}

	srv.AddTool(
		mcp.NewTool("dataroom_list",
			mcp.WithDescription("List all datarooms"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.ListDatarooms(ctx, client)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_create",
			mcp.WithDescription("Create a new dataroom with end-to-end encryption"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("title", mcp.Required(), mcp.Description("Dataroom title")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.CreateDataroom(ctx, cfg, client, req.GetString("title", ""), mcpPassphraseReader)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_info",
			mcp.WithDescription("Get dataroom metadata, file statistics, and member list"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("id", mcp.Required(), mcp.Description("Dataroom ID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			result, err := service.GetDataroomInfo(ctx, client, req.GetString("id", ""))
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(result)), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_ls",
			mcp.WithDescription("List nodes in a dataroom path. Supports glob patterns (*, ?, [...])"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("uri",
				mcp.Required(),
				mcp.Description("retyc:// URI, e.g. retyc://id or retyc://id/path or retyc://id/*.pdf"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			nodes, err := service.ListNodes(ctx, cfg, client, req.GetString("uri", ""), mcpPassphraseReader)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]any{"nodes": nodes})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_upload",
			mcp.WithDescription(
				"Upload one or more local files or directories to a dataroom. Directories are walked recursively. "+
					"This server process has FULL access to the local filesystem: it reads, encrypts (post-quantum AGE), "+
					"and uploads each file — plaintext never leaves the machine. "+
					"If the user gives a relative location ('bureau', 'desktop', 'downloads'), "+
					"call system_info to get home_dir, then ask for the exact folder name. "+
					"Pass absolute local paths only; do not read, stat, or enumerate files beforehand.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithArray("local_paths",
				mcp.Required(),
				mcp.Description("Local file or directory paths to upload"+absPathHint),
				mcp.Items(map[string]any{"type": "string"}),
			),
			mcp.WithString("remote_uri",
				mcp.Required(),
				mcp.Description("Destination retyc:// URI, e.g. retyc://id/folder"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var token mcp.ProgressToken
			if req.Params.Meta != nil {
				token = req.Params.Meta.ProgressToken
			}
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			localPaths := req.GetStringSlice("local_paths", nil)
			if err := service.UploadToDataroom(
				ctx, cfg, client,
				localPaths,
				req.GetString("remote_uri", ""),
				mcpPassphraseReader,
				mcpProgressFn(srv, ctx, token),
			); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_download",
			mcp.WithDescription(
				"Download a file (or glob of files) from a dataroom to a local directory. "+
					"Decryption happens in-process (post-quantum AGE); only metadata (filenames, sizes, paths) is returned — "+
					"do not read or relay the written files unless the user explicitly requests it.",
			),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("remote_uri",
				mcp.Required(),
				mcp.Description("Source retyc:// URI, e.g. retyc://id/file.pdf or retyc://id/*.pdf"),
			),
			mcp.WithString("local_dir",
				mcp.Required(),
				mcp.Description("Local destination directory"+absPathHint),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var token mcp.ProgressToken
			if req.Params.Meta != nil {
				token = req.Params.Meta.ProgressToken
			}
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			localDir := req.GetString("local_dir", "")
			if localDir == "" {
				return toolErr(fmt.Errorf("local_dir is required"))
			}
			files, err := service.DownloadFromDataroom(
				ctx, cfg, client,
				req.GetString("remote_uri", ""),
				localDir,
				mcpPassphraseReader,
				mcpProgressFn(srv, ctx, token),
			)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]any{"files": files})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_mkdir",
			mcp.WithDescription("Create a folder in a dataroom"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("uri",
				mcp.Required(),
				mcp.Description("retyc:// URI including the new folder name, e.g. retyc://id/parent/new-folder"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			nodeID, err := service.MkdirDataroom(ctx, cfg, client, req.GetString("uri", ""), mcpPassphraseReader)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]string{"node_id": nodeID})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_rm",
			mcp.WithDescription("Delete a node (file or folder) or the entire dataroom. Supports glob patterns."),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithString("uri",
				mcp.Required(),
				mcp.Description(
					"retyc:// URI to delete. retyc://id deletes the whole dataroom. Globs expand to multiple deletions.",
				),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			count, err := service.DeleteDataroomNode(ctx, cfg, client, req.GetString("uri", ""), mcpPassphraseReader)
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]int{"deleted_count": count})), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_mv",
			mcp.WithDescription("Move or rename a node within the same dataroom"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("src_uri",
				mcp.Required(),
				mcp.Description("Source retyc:// URI"),
			),
			mcp.WithString("dst_uri",
				mcp.Required(),
				mcp.Description("Destination retyc:// URI (must be in the same dataroom)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			if err := service.MoveDataroomNode(
				ctx, cfg, client,
				req.GetString("src_uri", ""),
				req.GetString("dst_uri", ""),
				mcpPassphraseReader,
			); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_user_add",
			mcp.WithDescription("Add a user to a dataroom and rekey it for all members"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithString("dataroom_id", mcp.Required(), mcp.Description("Dataroom ID")),
			mcp.WithString("email", mcp.Required(), mcp.Description("User email address to add")),
			mcp.WithString("role",
				mcp.Description("Role: \"viewer\" (default), \"editor\", or \"admin\""),
				mcp.DefaultString("viewer"),
				mcp.Enum("viewer", "editor", "admin"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			if err := service.AddDataroomUser(
				ctx, cfg, client,
				req.GetString("dataroom_id", ""),
				req.GetString("email", ""),
				req.GetString("role", "viewer"),
				mcpPassphraseReader,
			); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)

	srv.AddTool(
		mcp.NewTool("dataroom_user_rm",
			mcp.WithDescription("Remove a user from a dataroom and rekey it for remaining members"),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithString("dataroom_id", mcp.Required(), mcp.Description("Dataroom ID")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User ID to remove")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			cfg, client, err := newAPIClient(ctx)
			if err != nil {
				return toolErr(err)
			}
			if err := service.RemoveDataroomUser(
				ctx, cfg, client,
				req.GetString("dataroom_id", ""),
				req.GetString("user_id", ""),
				mcpPassphraseReader,
			); err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(`{"ok":true}`), nil
		},
	)
}

// mcpbTool matches the "tools" item schema of the MCPB manifest (v0.3).
type mcpbTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

var mcpToolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Print registered MCP tools as JSON (for MCPB manifest generation)",
	Long: `Print the list of MCP tools in the format expected by the MCPB manifest schema.

Output is a JSON array of {"name","description"} objects, suitable for use as
the "tools" field in an mcpb-manifest.json file. The CLI is the source of truth:
run this command and paste the output into your manifest to avoid duplication.

Example:
  retyc mcp tools | jq '.' > tools.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv := server.NewMCPServer("retyc", Version, server.WithToolCapabilities(false))
		registerMCPTools(srv)

		registered := srv.ListTools()
		tools := make([]mcpbTool, 0, len(registered))
		for _, st := range registered {
			tools = append(tools, mcpbTool{
				Name:        st.Tool.Name,
				Description: st.Tool.Description,
			})
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(tools)
	},
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	mcpCmd.AddCommand(mcpToolsCmd)
	rootCmd.AddCommand(mcpCmd)
}
