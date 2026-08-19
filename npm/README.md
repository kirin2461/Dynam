# dynam-ncp

npm wrapper for **[Dynam (NCP)](https://github.com/kirin2461/Dynam)** — a multi-layered
DPI-bypass and network privacy platform written in C++17. This package downloads the
prebuilt `ncp` CLI binary for your platform from
[GitHub Releases](https://github.com/kirin2461/Dynam/releases) during `postinstall`
and exposes it as the `dynam-ncp` (alias: `ncp`) command.

## Requirements

- Node.js >= 16
- Platform: `linux-x64`, `darwin-x64`, `darwin-arm64` (via Rosetta 2), `win32-x64`
- On Linux/macOS a system `tar` is used to unpack the release archive
  (Windows 10+ ships `bsdtar` as `tar.exe`, which also handles `.zip`)

## Install

```bash
npm install -g dynam-ncp
```

The postinstall script downloads the matching asset
(`ncp-linux-x64.tar.gz`, `ncp-macos-x64.tar.gz` or `ncp-windows-x64.zip`)
from the latest GitHub release, verifies it by running `ncp --help`, and installs
it into the package's `vendor/` directory.

> If your platform is not supported or the download fails, the install **does not
> fail** — you get a clear warning and can retry with `npm rebuild dynam-ncp`.

## Usage

All arguments are forwarded to the native `ncp` CLI:

```bash
# Show all commands
dynam-ncp --help

# Start PARANOID mode (all protection layers)
sudo dynam-ncp run

# Local SOCKS5/HTTP desync proxy (no admin needed)
dynam-ncp proxy --port 1080

# Single Packet Authorization: generate a key pair
dynam-ncp spa keygen --out my_spa

# Auto-select best DPI bypass strategy
dynam-ncp blockcheck

# Show version
dynam-ncp version
```

See the [full CLI documentation](https://github.com/kirin2461/Dynam#cli-tool)
in the main repository.

## Environment variables

| Variable | Description |
|---|---|
| `DYNAM_NCP_SKIP_DOWNLOAD=1` | Skip the binary download during install (CI/tests). |
| `DYNAM_NCP_BIN=/path/to/ncp` | Make the wrapper use an existing binary instead of the vendored one. |
| `DYNAM_NCP_RELEASE=v1.5.0` | Download from a specific release tag instead of `latest`. |
| `DYNAM_NCP_BASE_URL=https://...` | Override the releases base URL (mirrors/testing). |

## How it works

- `install.js` — platform/arch detection, download (follows GitHub CDN redirects),
  extraction, `chmod +x`, `--help` smoke test, graceful degradation.
- `bin/dynam-ncp.js` — thin wrapper: spawns the native binary with inherited
  stdio and propagates exit codes/signals.
- `.github/workflows/npm-publish.yml` (in the repo root) publishes this package
  on every GitHub release; a maintainer only needs to add the `NPM_TOKEN`
  repository secret.

## License

AGPL-3.0-only, same as the [Dynam](https://github.com/kirin2461/Dynam) project.
