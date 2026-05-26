# deploy

Deployment plumbing for the central server stack and agent provisioning. See root `README.md` §6.1 and §12 (Phase 0).

**Planned contents:**
- `docker-compose.yml` — OpenSearch + Redpanda + PostgreSQL + MinIO + Grafana.
- mTLS cert generator script (per-host client cert baked at install; pinned CA).
- Agent install/provisioning scripts (`scp`/`Copy-Item` single static binary).
- Grafana + OpenSearch Dashboards provisioning (pre-built MITRE ATT&CK heatmap).

**Status:** scaffold only — no compose/scripts yet.
