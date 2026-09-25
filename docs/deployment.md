# Deployment

## Local

```bash
scripts/install.sh
source .venv/bin/activate
beltu doctor --strict
beltu remote
```

## Remote/mobile

Use a TLS reverse proxy, HTTPS/WSS, explicit CORS origins, strong `BELTU_REMOTE_SECRET`, and restricted network access. Keep `.env`, database files, evidence, and backups out of source control. Review the scope file and enabled capabilities before starting an assessment.
