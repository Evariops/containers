# Evariops Container Images

Hardened, minimal container images — built from source, multi-arch, signed, and SBOM-attested.

Every image in this repository is:

- **Built from source** — no pre-built binaries from third parties
- **Multi-arch** — native `amd64` and `arm64` builds
- **`scratch`-based** — no shell, no package manager, minimal attack surface
- **Signed** — Sigstore cosign (keyless) with full provenance
- **SBOM-attested** — SPDX and CycloneDX attached as OCI attestations

---

## Available images

| Image | What it does | Upstream | Final size |
|-------|-------------|----------|------------|
| **[spdk]** | NVMe-oF TCP/RDMA storage engine | [spdk/spdk](https://github.com/spdk/spdk) | ~14 MB |
| **[fio]** | I/O benchmarking tool (static binary) | [axboe/fio](https://github.com/axboe/fio) | ~0.5 MB |

[spdk]: https://ghcr.io/evariops/spdk
[fio]: https://ghcr.io/evariops/fio

### Pull an image

```bash
# SPDK
docker pull ghcr.io/evariops/spdk:<tag>

# FIO
docker pull ghcr.io/evariops/fio:<tag>
```

---

## How tags work

There is no `latest` tag. All exact tags are **immutable**.

```
ghcr.io/evariops/spdk:v26.01.0   ← exact version, never changes
ghcr.io/evariops/spdk:v26.01     ← floating, follows the latest patch
```

The version scheme is **`v<upstream>.<patch>`** where the patch number tracks our rebuilds (Dockerfile changes, dependency bumps) of the same upstream release.

> Git tags follow the convention `spdk/v26.01.0`, `fio/v3.41.0`, etc.

---

## Verify a signature

All images are signed with [Sigstore cosign](https://docs.sigstore.dev/) (keyless — no keys to manage).

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/Evariops/containers/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/evariops/spdk:<tag>
```

## Inspect the SBOM

Both SPDX and CycloneDX SBOMs are attached to each image.

```bash
# View SPDX SBOM
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp="https://github.com/Evariops/containers/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/evariops/spdk:<tag> 2>/dev/null | jq -r '.payload' | base64 -d | jq .
```

Replace `spdxjson` with `cyclonedx` for the CycloneDX format.

---

## License

[Apache-2.0](LICENSE)
