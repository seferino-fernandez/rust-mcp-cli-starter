# MYAPP MCP Server

This server exposes the MYAPP API as tools.

- `myapp_get_system_status`: server health.
- `myapp_list_items`: list items (paginated: `page`, `page_size`).
- `myapp_get_item`: fetch one item by `id`.
- `myapp_create_item`: create an item (`name`, `enabled`).
- `myapp_delete_item`: delete an item by `id`. Destructive and cannot be undone.

Every tool rejects an argument it does not declare, so send only the listed
arguments.

Tools are described by the standard tool annotations. An OAuth access token
without the `write` scope may call only tools annotated read-only; any other
tool answers `insufficient_scope`.

Destructive tools may ask for confirmation through MCP form elicitation. Retry
the call with the same arguments, the returned request state and the user's
answer. This confirmation is a best-effort courtesy, not access control.

Replace these example tools with your API's operations.
