<!-- meta:title RTR file collection -->
<!-- meta:description Pulls one file off one host with the RTR Active Responder ``get`` command and returns only its metadata -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Pulls one file off one host with the RTR Active Responder ``get`` command and returns only its metadata

## API Scopes

- `Real time response:read`
- `Real time response:write`

## Tools

### `falcon_rtr_collect_file`

**Required scopes:** `Real time response:read`, `Real time response:write`

Collect one file from a host with RTR `get` and return its metadata.

Opens an RTR session, runs `get` as an Active Responder command, waits for
the upload, and returns the session ID, file name, SHA256 and size. The file
stays in the Falcon cloud as a 7z archive (password `infected`) for about
seven days; download it from the Falcon console. File contents are never
returned by this tool.
