# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

See our security policy and contact details at:
**https://retyc.com/.well-known/security.txt**

---

## Known Limitations (MCP server mode)

**Passphrase exposed as an environment variable**
`RETYC_KEY_PASSPHRASE` is passed to the MCP server via an environment variable. On some systems, environment variables of a running process may be readable by other processes belonging to the same user. Some MCP clients may also log or surface environment variables in their UI or debug output.

**The LLM can read metadata, never file content**
Tool responses may include transfer and dataroom metadata (filenames, sizes, timestamps, member lists, etc.) in plaintext - this data passes through the MCP client and the language model. File content, however, is end-to-end encrypted: it is decrypted locally and written directly to disk, and never included in tool responses.

**Transfer passphrases pass through the LLM**
Some transfers are protected by a per-transfer passphrase. If a tool requires one, the LLM may ask the user to provide it; that passphrase then transits the MCP client and the model context. Do not use a transfer passphrase that is reused elsewhere. To avoid this entirely, prefer key-based transfers by specifying the recipient's email address: the transfer is then encrypted to their public key and no passphrase is involved.

**Security depends on MCP client isolation**
The MCP server runs with full access to the Retyc token and passphrase. The confidentiality of these credentials depends on the isolation guarantees of the MCP client in use.
