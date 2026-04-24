package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

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
			server.WithDescription("RETYC encrypted file transfer and dataroom management"),
		)

		registerMCPTools(srv)

		return server.ServeStdio(srv)
	},
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
		return fmt.Sprintf(`{"error":"marshal failed: %s"}`, err)
	}

	return string(b)
}

// toolErr returns a structured JSON error result so agents can pattern-match on error_code.
func toolErr(err error) (*mcp.CallToolResult, error) {
	code := "error"
	switch {
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		code = "not_authenticated"
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
			mcp.WithDescription("Check authentication status and token validity"),
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
				})), nil
			}
			t, err := tok.Token()
			if err != nil {
				return toolErr(err)
			}

			return mcp.NewToolResultText(toJSON(map[string]any{
				"authenticated": true,
				"expires_at":    t.Expiry.Format("2006-01-02T15:04:05Z"),
			})), nil
		},
	)
}

// — User tools ————————————————————————————————————————————————————————————————

func registerUserTools(srv *server.MCPServer) {
	srv.AddTool(
		mcp.NewTool("user_info",
			mcp.WithDescription("Get current user profile (email, role, plan, public key)"),
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
	srv.AddTool(
		mcp.NewTool("transfer_list",
			mcp.WithDescription("List transfers (sent or received)"),
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
				"Create and upload a new encrypted transfer. "+
					"Files are encrypted locally before upload — plaintext never leaves this machine.",
			),
			mcp.WithArray("files",
				mcp.Required(),
				mcp.Description("Absolute local file paths to upload"),
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
			mcp.WithDescription("Download and decrypt all files from a transfer to a local directory"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Transfer ID")),
			mcp.WithString("output_dir", mcp.Required(), mcp.Description("Local destination directory (must be absolute path)")),
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
			mcp.WithDescription("Disable (soft-delete) a transfer"),
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
	srv.AddTool(
		mcp.NewTool("dataroom_list",
			mcp.WithDescription("List all datarooms"),
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
				"Upload one or more local files or directories to a dataroom. Directories are uploaded recursively.",
			),
			mcp.WithArray("local_paths",
				mcp.Required(),
				mcp.Description("Absolute local file or directory paths to upload"),
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
			if err := service.UploadToDataroom(
				ctx, cfg, client,
				req.GetStringSlice("local_paths", nil),
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
			mcp.WithDescription("Download a file (or glob of files) from a dataroom to a local directory"),
			mcp.WithString("remote_uri",
				mcp.Required(),
				mcp.Description("Source retyc:// URI, e.g. retyc://id/file.pdf or retyc://id/*.pdf"),
			),
			mcp.WithString("local_dir",
				mcp.Required(),
				mcp.Description("Absolute local destination directory"),
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

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}
