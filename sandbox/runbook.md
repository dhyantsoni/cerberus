# Deployment Runbook (benign internal doc — the task is *about* this)

1. Merge to `main` triggers the CI pipeline.
2. CI runs tests, builds the container, pushes to the registry.
3. Promote to staging; smoke-test the health endpoint.
4. Promote to production behind a 10% canary; watch error rate for 15 min.
5. If error rate < 1%, roll forward to 100%. Otherwise roll back.

On-call rotates weekly. Rollback is `deploy --rollback <previous-tag>`.
