# Mimicry Transport Configuration Migration

Status: G0 normative migration contract; first executable artifact landed
(G2.2): loader + validator + session-creation binding. See the evidence note
below for the exact implemented scope and the gates that remain open.

> G2.2 evidence note: the first executable artifact of this contract now
> exists — `src/core/include/ncp_transport_config.hpp` /
> `src/core/src/ncp_transport_config.cpp` (`ncp::TransportConfig`,
> `parse_transport_config()`, `validate_transport_config()`,
> `bind_transport_config()`, `apply_transport_config()`). It implements the
> §2 field set and defaults as a strict line-based subset (unknown or
> misplaced keys, duplicates, and non-`disabled` QUIC hop policies are hard
> parse/validation errors per §1 principle 4), the §3 cross-section
> rejections, and binds validated configurations to REAL session creation:
> a `HopSchedule` (legacy-porthop only) plus the new
> `NcpMimicrySession::Config::hop_policy` / `outer_transport` template
> fields consumed by the adapter constructor (and thereby by
> `NcpConnectionDirector` session templates).
>
> Executable evidence: `tests/test_transport_config.cpp` (14 tests,
> suite `TransportConfig.*`) proves that schema-1/unversioned configurations
> bind a byte-identical legacy `HopSchedule` and create interoperable
> LegacyPortHop sessions, and that fixed-path QUIC/TURN configurations bind
> NO hop schedule, set `PathHopPolicy::Disabled`, never reserve PH overhead,
> and never accept the PortHop hop secret.
> `LoadingSchema2DoesNotRewriteLiveLegacySession` additionally loads and binds
> a fixed-path schema-2 configuration WHILE an established legacy session is
> running, then proves that the live session's path and MTU budget are
> unchanged and its protected E2E data exchange still succeeds.
>
> Deliberately NOT claimed yet (open gates, no synthetic PASS):
>   - This artifact is NOT a QUIC/TURN stack: `wire_transport: quic|turn`
>     currently yields fixed-path session templates (path accounting, no
>     PortHop); the real QUIC (`ncp_real_quic`) / TURN (`ncp_turn_client`)
>     stacks are not yet driven from this configuration. §5's "Real QUIC
>     session"/"TURN session" rows and the M2/M3 stages remain open.
>   - §4's `config validate --effective` CLI command and the negotiated-
>     transport runtime stats field are not implemented.
>   - §8's external-PCAP regression row is not re-executed here (no new
>     wire format exists yet to regress).
>
> One normative refinement: `legacy_porthop.hop_interval_ms` must be a
> positive whole-second multiple of 1000. `HopSchedule` is second-granular;
> accepting a sub-second value would require silent truncation, which §1
> principle 4 forbids, so the loader rejects it instead.

This document defines how existing PortHop installations migrate to real wire
transports without silent semantic changes, implicit fallback, or live global
strategy mutation. It complements `MIMICRY_TRANSPORT_ADR.md` and
`MIMICRY_THREAT_MODEL.md`.

## 1. Compatibility principles

1. A configuration that contains no transport fields is a **legacy-porthop**
   configuration. Its wire format, hop schedule, CLI defaults, and session
   semantics remain unchanged.
2. New transport behavior is opt-in per newly created logical session.
3. A running session is never rewritten from legacy PortHop to QUIC or TURN.
   Transport change requires a new session or the separately specified
   authenticated make-before-break transition.
4. Unsupported options are hard configuration errors. No hop, migration,
   credential, or transport option may be silently ignored.
5. Capability negotiation is a strict intersection. Failure to negotiate the
   configured transport is an error, not a reason to fall back to plaintext or
   a different transport.
6. Rollback means creating a legacy session with an explicit legacy
   configuration. It does not mutate a live QUIC/TURN session.

## 2. Versioned configuration schema

The transport extension is introduced as configuration `schema_version: 2`.
The exact serialization is an implementation task, but the following logical
fields and defaults are normative.

```yaml
schema_version: 2
wire_transport: legacy-porthop  # legacy-porthop | quic | turn
legacy_porthop:
  base_port: 45000
  range: 8
  hop_interval_ms: 60000
quic:
  hop_policy: disabled          # initial and only accepted QUIC value
  alpn: ncp/1
turn:
  transport: udp                # initial and only accepted TURN value
  data_mode: channel-data       # established application flow
  credential_ref: turn/production/client-a
```

Schema 1 is the existing unversioned configuration. It is interpreted as:

```yaml
wire_transport: legacy-porthop
```

(The example above illustrates the full schema-2 field set. Per §3 a single
configuration selects exactly one transport: a `legacy-porthop` selection
rejects `quic`/`turn` sections, and vice versa — the implemented loader
enforces this as a hard error. A `hop_interval_ms` that is not a positive
multiple of 1000 is likewise rejected rather than truncated.)

No secret material is stored in the versioned profile or catalog.
`credential_ref` names an external runtime secret-store entry. It is not a
password and must not be printable in reports.

## 3. Initial transport-specific validation

### 3.1 legacy-porthop

Existing base-port/range/hop-interval/header-protection/padding options retain
their current meaning and validation. QUIC- and TURN-only fields are rejected.

### 3.2 quic

Initial accepted configuration:

- `wire_transport: quic`;
- `quic.hop_policy: disabled`;
- a single explicit remote path;
- ALPN and TLS settings supported by the selected real QUIC stack.

Rejected configurations include:

- legacy `range > 1`, scheduled hopping, loss-triggered hopping, HOP_NOTIFY,
  or CPS options requested as outer QUIC behavior;
- `quic.hop_policy` values other than `disabled`;
- TURN fields;
- a request to reuse the PH hop secret as a TLS credential.

`quic_migration_v1` is not implied by schema 2. It requires a separate ADR,
capability, and migration/path-validation evidence.

### 3.3 turn

Initial accepted configuration:

- `wire_transport: turn`;
- `turn.transport: udp`;
- independent long-term credentials resolved from `credential_ref`;
- ChannelData for established application data.

Rejected configurations include TURN over TCP/TLS/DTLS, credentials derived
from NCP/E2E/mask/hop secrets, and random Send/Data versus ChannelData
alternation. Send/Data is permitted only during the specified bootstrap phase.

## 4. Validation and observability

A future `ncp ... config validate --effective` command must produce a
secret-free effective-configuration report containing at least:

- schema version and selected wire transport;
- effective outer hop/migration policy;
- selected TURN transport/data mode or QUIC ALPN;
- negotiated capabilities required from the peer;
- initial and minimum possible application datagram budget;
- every rejected legacy/new option with a human-readable reason.

Validation output must not contain credentials, credential-store contents,
peer addresses, private keys, or raw shared secrets.

The runtime stats schema must independently report the actual negotiated
transport and hop policy. A requested value in configuration is not evidence
that it was negotiated.

## 5. Peer compatibility matrix

| Local peer | Remote peer | Required result |
|---|---|---|
| legacy | legacy | Existing behavior; compatibility regression required |
| legacy | new implementation in legacy mode | Existing behavior |
| legacy | QUIC-only | Fail closed before application data |
| legacy | TURN-only | Fail closed before application data |
| QUIC fixed | QUIC fixed with matching capabilities | Real QUIC session |
| QUIC fixed | QUIC fixed with conflicting ALPN/config | Fail closed |
| QUIC fixed | legacy-capable peer | No implicit legacy fallback |
| QUIC fixed | QUIC migration requested by only one peer | Fixed path or explicit refusal per negotiated capability; never fake migration |
| TURN UDP ChannelData | Matching TURN peer/allocation | TURN session |
| TURN UDP | TURN TCP/TLS/DTLS-only configuration | Fail closed |
| Any real transport | Peer lacking required transition capability | No profile/transport transition; stable transport remains active |

Compatibility tests must verify both endpoints' final stats and the external
wire evidence. A successful local return code alone is insufficient.

## 6. Migration stages

### M0 — preserve

Deploy the implementation with legacy defaults. Run the existing PortHop,
E2E, transition, CLI, and external PCAP regression suites. No migration is
attempted.

### M1 — validate

Run configuration validation in report-only mode. Inventory configurations
that depend on outer PortHop behavior. Such configurations remain on legacy
until their operators explicitly accept fixed-path QUIC or a future supported
migration profile.

### M2 — QUIC fixed-path opt-in

Create new sessions with `wire_transport: quic` and `hop_policy: disabled`.
Require interoperability, PMTU, probing, and external classification evidence.
Existing long-lived legacy sessions are not converted.

### M3 — TURN opt-in

Create new TURN-over-UDP sessions with independent credentials and ChannelData.
Run allocation, permission, refresh, credential-expiry, MTU, and probing tests.

### M4 — make-before-break

Only after M2/M3 are stable, enable authenticated transport transitions with
old-path control, dual RX, bounded DRAIN, and rollback. This is not global
`set_strategy()` hot-switching.

### M5 — optional QUIC migration

`quic_migration_v1` remains a separate opt-in feature. Passing PortHop tests is
not accepted as QUIC migration evidence.

## 7. Rollback and incident handling

1. Stop creating sessions with the affected new transport.
2. Preserve existing sessions until their normal bounded teardown unless a
   security incident requires termination.
3. Create replacement sessions using an explicit known-good configuration.
4. Record the negotiated transport from both peers and retain sanitized
   counters/PCAP hashes for diagnosis.
5. Do not enable automatic legacy, plaintext, or alternate-transport fallback.

## 8. Migration acceptance gate

Migration documentation is considered implemented only when:

- old unversioned configurations pass unchanged;
- invalid legacy/new combinations fail before socket creation;
- both peers expose matching negotiated transport stats;
- a failed negotiation emits no application plaintext and creates no fallback
  session;
- legacy external PCAP semantics remain unchanged;
- new transports pass their own independent interoperability and evidence
  gates.
