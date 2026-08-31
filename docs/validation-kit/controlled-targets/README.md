# Controlled report targets

This stack creates three isolated Docker targets for the first report-usability review:

- `172.30.0.9`: Ubuntu 22.04 OpenSSH (`8.9p1` banner on current packages)
- `172.30.0.10`: nginx HTTP with version disclosure disabled
- `172.30.0.11`: nginx TLS with a seven-day self-signed certificate

The network is an isolated Docker bridge. Do not replace the target CIDR with a real network unless the network owner has authorized the scan.

```bash
docker compose up -d --build ssh-target http-target tls-target
docker compose --profile report run --rm report-generator
docker compose down
```

The report generator uses the published `0.9.7` image and writes `docs/validation-report.html`. A completed report is review material, not evidence that user interviews or report reviews occurred.
