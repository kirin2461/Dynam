# NCP (Dynam) server deployment — AmneziaWG 3.1 + NCP modules

One command on a clean server brings up the full stack:

```bash
cd deploy
sudo ./install.sh
```

## What gets deployed

| Container | Role |
|---|---|
| `dynam-awg` | AmneziaWG 3.1 transport (userspace `amneziawg-go`), MTU 1280, unique H1–H4/S1–S4/`HeaderProtectionKey`/`ContentPaddingAddition` per installation |
| `dynam-ncp-spa` | `ncp spa serve` — service ports stay a black hole until an Ed25519-signed knock opens the ipset gate |
| `dynam-ncp-reality` | `ncp reality serve` — TLS front with fallback to a real site; authorized clients carry an Ed25519 token in the SNI label |
| `dynam-ncp-porthop` | `ncp porthop serve` — UDP port-hopping with AWG 3.1 hardening (HKDF header prefixes, randomized version range, content padding, hop-interval range) |

## Unique parameters per installation

`install.sh` regenerates everything on each install, so no universal DPI
rule can match the deployment: AWG H1–H4/S1–S4/Jc/Jmin/Jmax/
`HeaderProtectionKey`, AWG + SPA + reality keypairs, porthop HMAC and
header-protection secrets, version range, hop-interval range, all ports.

## Files

- `.env` — all parameters (mode 600, generated, never commit)
- `secrets/` — SPA/reality key material (mode 700)
- `awg/awg0.conf` — rendered AmneziaWG server config (mode 600)
- `client-configs/` — what you copy to the client: `awg-client.conf`
  (import into AmneziaVPN 3.1+), `spa-client.key`, `ACCESS.txt`
  (exact commands for knock / porthop / reality)

## Client flow

1. `ncp spa knock <server> --key spa-client.key --allow-port <AWG_PORT> --proto udp`
2. Import `awg-client.conf` into AmneziaVPN 3.1+ and connect.
3. Fallback when the transport is unreachable: `ncp proxy --autopilot`.

## Removal

```bash
sudo ./uninstall.sh
```

Removes containers, images, firewall rules, the ipset gate, all keys and
configs. SSH is never touched by either script.

## Security notes

- Run the installer yourself on your own server; no third-party access.
- Never commit or send `.env`, `secrets/`, `client-configs/`.
- After installing, switch SSH to key-only auth
  (`PasswordAuthentication no`) and enable fail2ban.
