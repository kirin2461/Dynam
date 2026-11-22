# Plan: Statistical AutoPilot (Bandit selection + change detection)

> **Status**: Proposal, not started. Nothing in this document is implemented.
> **Date**: 2026-11-16
> **Scope**: C++ core (`autopilot.cpp`, `preset_autopilot.cpp`), web UI (`web/`), tests. §7 lists web UI defects to fix independently.
> **Wire protocol**: unchanged. No PortHop / E2E / mimicry format changes.

---

## 1. Problem

Strategy choice and block detection today use fixed rules:

| Where | Current rule | Weakness |
|---|---|---|
| `AutoPilot` (per host), `ncp_autopilot.hpp` | `degrade_threshold = 3` consecutive failures → `degraded`, then relearn | A strategy with 500 successes is dropped after 3 unlucky failures; a slow, partial block (e.g. 40% failures, never 3 in a row) is never detected |
| `PresetAutoPilot`, `preset_autopilot.cpp:286` | `score = success_count * 100000 - avg_latency_ms` over one probe round | One round of a few probes decides; no memory of past rounds; no confidence; ties broken by latency noise |
| Escalation L0→L3 | Fixed rounds / cooldowns (`escalation_cooldown_sec = 300`, `deescalate_direct_rounds = 3`) | Escalation speed doesn't depend on how strong the evidence is |
| Web UI (`/api/monitor/autopilot`) | Shows `successes/failures` and a `degraded` flag | User can't see how confident the AutoPilot is or why it switched |

## 2. Approach

Two pieces of standard statistics, both small and local to AutoPilot:

### 2.1 Thompson sampling over strategies (selection)

For each `(key, strategy)` pair keep a **Beta(α, β)** posterior of the success probability. `key` is the host for `AutoPilot` and the network/preset context for `PresetAutoPilot`.

- **Prior**: `α₀ = 1, β₀ = 1` (uniform). Strategies imported from a zapret preset or a previous learn may start with a stronger prior (e.g. `α₀ = 2`).
- **Update** on each outcome: success → `α += 1`, failure → `β += 1`. RST, timeout and TLS failures all count as failures; the reason is kept separately for change detection (§2.2).
- **Forgetting** (blocking rules change over time): before each update, decay toward the prior:
  `α ← α₀ + γ^Δt · (α − α₀)`, `β ← β₀ + γ^Δt · (β − β₀)`, with half-life configurable (default 24 h, i.e. `γ = 0.5^(1/86400)` per second). This keeps the effective sample size bounded, so the posterior can move again after a policy change.
- **Selection**: draw `θᵢ ~ Beta(αᵢ, βᵢ)` for every candidate, choose `argmax θᵢ`. Latency becomes a tie-breaker inside a tolerance: among candidates whose `θ` is within 0.02 of the best, prefer the lower `ewma_latency_ms`.
- **RNG**: draws use the existing `ncp::CSPRNG` (§ PATCHES Phase 0). A Beta draw is two Gamma draws (Marsaglia–Tsang); with integer-ish parameters this is cheap.
- **Exploration cost cap**: live traffic should not be spent on hopeless strategies. A candidate whose posterior mean is below `min_mean` (default 0.05) **and** has ≥ 20 effective trials is only re-tried by the background relearn janitor, not on live connections.

What this fixes: a long-proven strategy survives a short bad patch (its posterior is narrow); a new block still shows up quickly once failures dominate; new candidates get explored in proportion to their uncertainty instead of by fixed order.

### 2.2 Change detection (when to relearn / escalate)

Replace "3 consecutive failures" with a **Bernoulli CUSUM** on the active strategy's outcome stream:

- Baseline rate `p₀` = posterior mean of the active strategy when it was (re)selected.
- Alternative `p₁ = p₀ · ρ` with `ρ = 0.5` (default: "success rate halved").
- Per outcome `x ∈ {0,1}`: `S ← max(0, S + log-likelihood ratio(x))`, where the LLR is `log(p₁/p₀)` on success and `log((1−p₁)/(1−p₀))` on failure.
- Alarm when `S ≥ h`. `h` is chosen for a target false-alarm rate (default average run length to false alarm ≈ 1000 outcomes; `h` computed once from `p₀, p₁` with the Siegmund approximation and cached, recomputed when `p₀` changes).
- On alarm: mark the record `degraded` (same field as today → UI and janitor keep working), reset `S`, trigger relearn / next escalation step.
- **RST fast path**: an RST-injection burst is a strong, specific signal. Keep a separate small CUSUM on the `rst` share (blockcheck already reports `rst` again after R17-07). Its alarm may skip directly to escalation.

Keep the old rule as a **safety net**: if `consec_failures ≥ hard_threshold` (default 8), degrade regardless of CUSUM. This bounds the worst case if the statistics are misconfigured.

### 2.3 Escalation driven by evidence (PresetAutoPilot)

- Keep one Beta posterior per preset (and one for `direct`), updated by every probe round instead of scoring rounds in isolation.
- **Escalate L1→L2→L3** when, for every preset, `P(θ_preset > acceptability threshold) < 0.1`, i.e. we're confident none of them is acceptable. This replaces "presets exhausted in one round".
- **De-escalate** when `P(θ_direct > threshold) > 0.9`, replacing `deescalate_direct_rounds = 3`.
- `escalation_cooldown_sec` stays as an upper bound on escalation frequency.

## 3. Changes by component

### 3.1 C++ core

| File | Change |
|---|---|
| `src/core/include/ncp_bandit.hpp` (new, header-only) | `BetaPosterior { double alpha, beta; void decay(dt); void update(bool); double mean(); double sample(CSPRNG&); double prob_above(double t); }` and `BernoulliCusum { p0, p1, h, S; bool update(bool); }`. `prob_above` uses the regularized incomplete beta function (continued-fraction, ~40 lines). No new dependency. |
| `ncp_autopilot.hpp` | `AutoPilotRecord`: add `double alpha = 1, beta = 1; double cusum_s = 0; double cusum_p0 = 0; int64_t posterior_ts = 0;` (keep all existing fields). `Config`: add `selection = Selection::Threshold \| Selection::Bandit` (default `Threshold` until rollout §6), `half_life_sec`, `cusum_rho`, `cusum_arl0`, `hard_degrade_threshold`, `min_mean`. |
| `autopilot.cpp` | `report_success/failure`: decay + update posterior, update CUSUM, set `degraded` from CUSUM (Bandit mode) or the existing rule (Threshold mode). `learn()`: rank probe results by Thompson draws instead of first-success. JSON: write the new fields; missing fields on load → defaults (old DBs keep working). |
| `ncp_preset_autopilot.hpp`, `preset_autopilot.cpp` | Per-preset posteriors replace the `success_count * 100000 - latency` score when Bandit mode is on; escalation/de-escalation conditions per §2.3. Stats JSON gains `posteriors: [{preset, mean, ci_low, ci_high, trials}]` and `cusum: {s, h}`. |
| `src/cli/main.cpp` | `ncp autopilot status` prints mean and 90% credible interval per record. Flags: `--selection threshold\|bandit`, `--half-life <sec>`. |

### 3.2 Web UI

Findings from reviewing `web/`:

- Backend: Flask + Flask-SocketIO (`web/server.py`, `web/bypass_routes.py`). The per-host AutoPilot panel calls `GET /api/monitor/autopilot`, which **reads `autopilot.json` directly** (`_read_autopilot_db`, `bypass_routes.py:670`) and returns a fixed set of fields per record.
- The PresetAutoPilot badge is fed from the engine's stats JSON, which `server.py:862` passes through verbatim in the `/ws` `stats` event. `app.js:renderPresetAutopilot` already handles optional v2 fields (`level_name`, `geneva`) and hides what's missing, so new optional fields are backward compatible.
- Front end: plain JS (`web/static/js/app.js`, ~2650 lines), Chart.js available (`charts.js`), UI strings in Russian, HTML built with template strings (existing code escapes user values; keep doing so).

Planned changes:

| File | Change |
|---|---|
| `web/bypass_routes.py` `api_monitor_autopilot` | Also return `alpha`, `beta`, `mean = α/(α+β)`, 90% credible interval (computed in Python with a small incomplete-beta helper or `scipy`-free approximation), `cusum_s`, `cusum_h`. Missing fields in older DBs → omit, UI falls back to today's view. |
| `web/static/js/app.js` `monitorAutopilotPoll` | Table column "Успехи/Неудачи" → **"Надёжность"**: `87% (79–93%)` plus a thin bar showing the interval. Status column shows the CUSUM level as "тревога: 40%" (`S/h`) before it turns `degraded`. Keep `successes/failures` in a tooltip. |
| `app.js` `renderPresetAutopilot` | Tooltip lists presets with mean ± interval; badge text unchanged. |
| `web/static/js/charts.js` | Optional small chart: posterior mean of the active strategy over time with interval band, and CUSUM `S` against threshold `h`. Same Chart.js setup as the traffic chart. |
| `web/static/js/help.js` | Help entry explaining "Надёжность" and "тревога" in plain words. |
| Settings panel (`index.html`) | Toggle "Статистический автопилот (beta)" → writes `autopilot_selection` into the config the web panel passes to `ncp` (`--selection bandit`). |
| `web/pentest.py` | No change needed; it only checks that the AutoPilot section exists. |

### 3.3 Tests

| Test | What it proves |
|---|---|
| `tests/test_bandit.cpp` (new) | Beta update/decay math; `sample()` mean converges (10⁵ draws, tolerance); `prob_above` against known values; CUSUM ARL₀ / detection delay on simulated Bernoulli streams within tolerance. |
| `tests/test_autopilot*.cpp` (extend, using the existing `report_fn` hook) | (a) A strategy with 200 successes survives 3 failures in Bandit mode, is degraded in Threshold mode. (b) A 100%→40% success drop is detected within N outcomes (N from the CUSUM design). (c) Old `autopilot.json` without new fields loads and behaves like a fresh prior. (d) Hard safety net still degrades at 8 consecutive failures. |
| `tests/test_preset_autopilot.cpp` (extend) | Escalation fires only when all presets are confidently below threshold; de-escalation per §2.3. |
| Web: `tests/test_*` (pytest, if present) or manual | `/api/monitor/autopilot` with old and new DB files; UI renders both. |
| Simulation harness (`scripts/lab/`) | Replay of synthetic block schedules (sudden block, gradual throttling, flapping) comparing Threshold vs Bandit: time-to-detect, false relearns, share of live connections on a working strategy. This is the acceptance evidence. |

## 4. Acceptance criteria

On the simulation harness, Bandit mode vs current Threshold mode:

1. **Detection**: sudden full block detected no slower than today (≤ 3 outcomes on a strong prior shift); 60% partial block detected (today: usually never).
2. **Stability**: false relearns on a healthy strategy with 5% random failures reduced by ≥ 5×.
3. **Live success rate**: share of live connections routed to a working strategy ≥ Threshold mode on every scenario.
4. No regressions: existing ctest targets green; old `autopilot.json` files load.

## 5. Milestones

| # | Deliverable | Size |
|---|---|---|
| M1 | `ncp_bandit.hpp` + `test_bandit.cpp` | S |
| M2 | AutoPilot record fields, JSON compat, Bandit/CUSUM behind `--selection bandit` (default off) + tests | M |
| M3 | Simulation harness + Threshold vs Bandit report | M |
| M4 | PresetAutoPilot posteriors + evidence-based escalation + tests | M |
| M5 | Web UI: API fields, "Надёжность" column, tooltip, help, settings toggle | M |
| M6 | Optional charts (posterior + CUSUM) | S |
| M7 | Default `selection = bandit` after M3 criteria pass | — |

## 6. Rollout and risks

- **Default off** until M3 shows the acceptance criteria are met; then flip the default and keep `--selection threshold` as a fallback.
- **JSON compatibility**: new fields are additive; old readers (including current web panel) ignore them; new readers treat missing fields as the prior.
- **Exploration on live traffic**: bounded by `min_mean` + background-only retries (§2.1).
- **Mis-tuned CUSUM**: hard consecutive-failure safety net (§2.2).
- **Determinism in tests**: inject the RNG / use `report_fn`, as existing AutoPilot tests do.

## 7. Web UI fixes (independent of the AutoPilot work)

Found by reading `web/` (Flask + Flask-SocketIO backend, plain-JS front end) on 2026-11-16. **Code reading only, nothing run or reproduced.** These are defects in the current panel and should be fixed before or alongside M5, because M5 adds more rendering to the same tables.

What is already done well and should be kept: `/api/*` requires a per-start `X-NCP-Token`, a loopback `Host` (DNS-rebinding guard) and a loopback `Origin`/`Referer` (`server.py:283–307`); every `subprocess` call uses an argument list (no `shell=True`); updates are checked against both a SHA-256 and an Ed25519 signature (`ncp_update.py:98–194`); archive member names are validated (`_is_safe_member_name`).

### 7.1 Must fix

| ID | Where | Problem | Fix |
|---|---|---|---|
| W-01 | `static/js/app.js:2086`, `2091`, `2094`, `2113` (monitor event feed + host table) | **Stored XSS.** `ev.host`, `ev.strategy`, `ev.result`, `r.strategy` go into `innerHTML` unescaped. `host` comes from the SOCKS CONNECT request (`src/core/src/ncp_proxy.cpp:1325`), which a client can fill with arbitrary bytes; the C++ side only JSON-escapes it. Script running in the panel can read the API token from `<meta name="ncp-token">` and call every `/api/*` route (start processes, install updates, change config). | Escape every interpolated value with the existing `_esc()` / `escapeHtml()` (`app.js:1259`, `1592`), or build these rows with `textContent`. Colour values should come only from the fixed `colors` map. |
| W-02 | `app.js:902–909` (E2E sessions), `948–955` (I2P tunnels), `1197` (rotation history), `380` (module rows) | Same pattern: server-returned fields (`s.peer`, `s.cipher`, `t.destination`, `t.type`, `h.ts`) interpolated into `innerHTML` without escaping. `peer` / `destination` are user- or network-supplied. | Same fix as W-01. Add a lint rule or a small grep-based CI check: every `${…}` inside an `innerHTML` template must be wrapped in `_esc()` unless it's a constant. |
| W-03 | `server.py:309–310` | CORS and Socket.IO `cors_allowed_origins` are hard-coded to port `8085`, but the port comes from `NCP_WEB_PORT` (`server.py:2344`). With any other port the panel's own Socket.IO connection is rejected as cross-origin, so live stats, logs and the AutoPilot badge silently stop updating. | Build the origin list from the actual port at startup (`127.0.0.1:{port}`, `localhost:{port}`). |

### 7.2 Should fix

| ID | Where | Problem | Fix |
|---|---|---|---|
| W-04 | `server.py:2204` (`/ws` connect) | Socket.IO connections are not token-checked; only the CORS origin list protects them. The `/ws` stream carries logs and stats (hostnames, strategies). A non-browser local process can subscribe freely. | Require the API token in the Socket.IO `auth` payload and reject the connect handler without it; `websocket.js` passes it from the meta tag. |
| W-05 | `bypass_routes.py:812` (`/api/monitor/autopilot/learn`) | The domain is only checked for spaces and `/`. A value starting with `-` is passed to `ncp autopilot learn <domain>` as an argument and can be parsed as a CLI option. Same pattern may exist in other routes passing user input to `ncp`. | Validate with the existing `_HOST_RE` (`bypass_routes.py:970`), as `/api/hostlist/add` already does, and insert `--` before positional arguments where the CLI supports it. Audit all `args = [ncp_binary, …]` sites for the same issue. |
| W-06 | `server.py:2376` | `socketio.run(..., allow_unsafe_werkzeug=True)` runs the Werkzeug development server in production. | Use the `threading` mode with a production-capable server (e.g. `simple-websocket` + `waitress`), or `eventlet` (already in `requirements.txt`) and drop `allow_unsafe_werkzeug`. |
| W-07 | `bypass_routes.py:670` (`_read_autopilot_db`) | Corrupt or partially written `autopilot.json` silently returns "no records", so the panel shows "Нет выученных хостов" instead of an error. Can happen when the C++ side is mid-write. | Return an explicit `error` field and show it in the panel; ensure the C++ writer uses write-to-temp + rename (check `autopilot.cpp` save path). |
| W-08 | `bypass_routes.py:1155` (`/api/update/install`) | Install runs synchronously inside the request (download up to 120 s, `ncp_update.py:186`), blocking a server thread with no progress shown. | Run in a background thread like `_run_ap_learn`, expose progress via a status route. |

### 7.3 Nice to have

- `requirements.txt`: pin upper bounds for `flask`, `flask-socketio`, `eventlet` (only `fpdf2` is pinned), so a major release can't break the panel.
- `app.js` is ~2650 lines in one file; split per tab (monitor, autopilot, pentest, enterprise) before M5 adds more.
- UI strings are hard-coded in Russian in JS and HTML; move them to one dictionary if an English UI is wanted.

### 7.4 Verification

- W-01/W-02: a test proxy event with `host = "<img src=x onerror=alert(1)>"` must render as text. Add a pytest that writes such a line to `proxy_events.jsonl` and checks `/api/monitor/events` returns it unchanged, plus a short manual browser check (or a Playwright test if adopted).
- W-03: start the panel with `NCP_WEB_PORT=9090` and confirm live stats update.
- W-04: Socket.IO client without token is refused; panel still connects.
- W-05: `POST /api/monitor/autopilot/learn {"domain": "--help"}` returns 400.

### 7.5 Milestone

| # | Deliverable | Size |
|---|---|---|
| W1 | W-01, W-02, W-03 + checks from §7.4 | S |
| W2 | W-04, W-05, W-07 | S |
| W3 | W-06, W-08 and the §7.3 items | M |

W1 should land **before** M5, since M5 adds new values to the same tables.

## 8. Backlog (later ideas, not in this plan)

1. **Mimicry quality metrics**: Wasserstein / Jensen–Shannon / KS distances between generated traffic and the target `StatProfile`, as a CI gate. Check `ncp_adversary_tester` first; parts may exist.
2. **Optimal-transport shaping**: quantile-matching map from real to target packet sizes to minimise padding for a given profile.
3. **Fountain / RLNC coding** for PortHop/QUIC control traffic (handshake, caps, transition control) instead of timeout-based resend.
4. **Reachability-weighted port hopping**: HMAC-seeded port choice weighted by per-port reachability, with a min-entropy bound on predictability.
