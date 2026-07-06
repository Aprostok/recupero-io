# Recupero infrastructure (Terraform + Kubernetes)

Infrastructure-as-code for the multi-tenant SaaS (`docs/PLATFORM_ARCHITECTURE.md`
§6.9). Two layers:

```
infra/
├── terraform/         # cloud data plane: Postgres, Redis, object storage, secrets
│   ├── main.tf        # RDS Postgres (primary+replica), ElastiCache Redis, S3 artifacts, IAM, secrets
│   ├── variables.tf   # region, sizing, retention knobs
│   └── outputs.tf     # DSNs / endpoints wired into the k8s secret
└── k8s/               # compute plane: API + worker + scheduler, autoscaled
    ├── namespace.yaml
    ├── secret.example.yaml   # template — real secrets come from Terraform outputs / a secret manager
    ├── api-deployment.yaml   # FastAPI /v1 + /v2 (uvicorn), readiness on /healthz
    ├── api-hpa.yaml          # scale API on CPU + requests-per-second
    ├── worker-deployment.yaml
    ├── worker-scaledobject.yaml  # KEDA: scale workers on investigations queue depth
    ├── scheduler-deployment.yaml # the cron scheduler (HA leader-lock, migration 029)
    └── ingress.yaml
```

## Scaling model (matches the architecture doc)

- **API** scales on **RPS + CPU** (stateless; shared Redis rate-limiter +
  API-key cache mean N replicas behave as one — `RECUPERO_REDIS_URL`).
- **Workers** scale on **queue depth** — KEDA polls
  `SELECT count(*) FROM investigations WHERE status='queued'` and scales the
  Deployment 0→N. The queue is `FOR UPDATE SKIP LOCKED`, so any number of
  workers drain it safely.
- **Scheduler** runs 1–2 replicas; the DB leader-lock (migration 029) ensures a
  job fires once even with two schedulers.
- **Postgres** primary + read replica; **Redis** single node (rate-limit +
  key-cache; both fail open, so a Redis blip never takes the API down).
- **Object storage**: S3 bucket with a per-org key prefix and a lifecycle rule
  that expires artifacts (backstop to the app's per-plan retention cron).

## Apply

```bash
cd infra/terraform
terraform init && terraform apply          # provisions data plane
terraform output -json > ../k8s/tf-outputs.json

cd ../k8s
# materialise secret.yaml from tf-outputs.json + your app secrets, then:
kubectl apply -f namespace.yaml -f secret.yaml
kubectl apply -f api-deployment.yaml -f api-hpa.yaml -f ingress.yaml
kubectl apply -f worker-deployment.yaml -f worker-scaledobject.yaml
kubectl apply -f scheduler-deployment.yaml
```

Migrations run once per deploy (init container / one-shot Job) via
`python -m recupero.ops apply-migration migrations/NNN_*.sql` in numeric order.

> These manifests are a production-shaped starting point, not a turnkey cluster:
> pin image digests, set real resource requests from load tests, and source all
> secrets from your cloud secret manager (never commit `secret.yaml`).
