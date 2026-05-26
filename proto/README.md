# proto

Shared Protobuf schema for the agent↔server wire protocol. See root `README.md` §4.

- **Transport:** gRPC bidirectional streaming over HTTP/2, mTLS, pinned CA.
- **Event schema:** Protobuf modeled on **Elastic Common Schema (ECS)** field names
  (`process.parent.executable`, `destination.ip`, `event.action`, `host.hostname`, `host.os.type`)
  so detection content ports cleanly to Sigma / Elastic.
- Single source of truth consumed by both `agent-linux/`, `agent-windows/`, and `server/`.

**Status:** scaffold only — `.proto` files not written yet.
