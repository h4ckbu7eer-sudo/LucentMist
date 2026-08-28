# Known Issues

Current status as of 0.9.3.

## Product Limitations

- Built-in CVE database is small and heuristic. It is not equivalent to Nmap/Nessus fingerprinting.
- Service version detection depends on banner format; many real-world banners will not produce exact versions.
- SMB dialect and OpenSSH thresholds have been corrected, but the full detection pipeline still needs controlled-network validation.

## Agent

- Agent analysis is experimental.
- Default local model qwen2.5:7b scored 0/10 in real LLM evaluation.
- Claude validation is pending.
- Contract violations now produce a visible degradation warning.

## Testing

- CI runs `--filter "Category!=External"`. The filtered count changes as tests are added; do not treat a single number as a frozen contract.
- Local full runs include external SSL tests and may show a different count.
- Test counts in docs are being reconciled to this two-track statement.

## Deployment

- Docker compose auto-generates random credentials and prints them to container logs.
- Production deployments must override credentials through `.env`.
