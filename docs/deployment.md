# Deployment

## Local

```bash
python3 -m pip install -e . --no-build-isolation
beltu doctor --strict
beltu remote serve
```

## Remote/mobile

Use a TLS reverse proxy, HTTPS/WSS, explicit CORS origins, strong `BELTU_REMOTE_SECRET`, and restricted network access. Keep `.env`, database files, evidence, and backups out of source control. Review the scope file and enabled capabilities before starting an assessment.
