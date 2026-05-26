# server

Central server — **Go** (single binary per team subnet). See root `README.md` §6.

**Components:**
- **Ingest:** gRPC bidi stream over mTLS (pinned CA), Protobuf ECS-shaped events (`proto/`).
- **Bus:** Redpanda (Kafka API) — decouples ingest from detection, enables scored-window replay.
- **Detection runtime:** SigmaHQ → ES|QL at 30s cadence + custom stateful IOAs walking the `lineage_id` graph; YARA worker (`hillu/go-yara`).
- **Response orchestrator:** pushes signed commands down the agent stream (kill/isolate/quarantine/collect).
- **Stores:** OpenSearch (hot search) + PostgreSQL (metadata) + MinIO (raw archive).

**Guardrail (review finding):** destructive auto-responses must respect a hard "scored-service" allowlist and a human-confirm tier until tuned. Do not auto-delete/auto-revert into a scored outage.

**Status:** scaffold only — no code yet.
