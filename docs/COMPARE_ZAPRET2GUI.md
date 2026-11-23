# Dynam vs. Zapret 2 GUI — DPI-Bypass Strategy Engine Gap Analysis

**Task 8 comparison doc.** Compares Dynam (NCP C++, v1.7.6, AGPLv3) against the
Zapret 2 GUI project (`zapret-discordyoutube/zapretgui`, MIT, Python/Windows).

- **Baseline fetched:** repo README + `src/`, `docs/`, and
  `src/system/strategy_catalogs/winws2/tcp.txt` (live, Nov 2026).
- **Dynam side:** read locally from `src/core/src/*.cpp` and `docs/`. All Dynam
  claims cite `file:line`.
- **Scope caveat:** nothing here was runtime-tested or compiled. Dynam has no
  compiler/git in this environment; zapretgui was read as source only. Marked
  `[unverified]` where a claim could not be confirmed from code.

---

## 1. Executive summary

- **Different product categories.** zapretgui is a **Python GUI launcher** that
  orchestrates prebuilt `winws.exe`/`winws2.exe` (bol-van zapret) kernels and
  ships **200+ ready strategies** for Discord/YouTube. Dynam is a **self-contained
  C++ DPI-bypass engine** (own WinDivert/raw-socket packet path, own fake/split
  logic) plus a much broader anti-censorship transport stack — it is not a
  launcher for an external kernel.
- **Strategy breadth favors zapretgui; engine depth favors Dynam.** zapretgui's
  catalog is a huge, community-curated, per-ISP strategy library expressed in
  zapret's new `--lua-desync=` DSL. Dynam ships ~**13 hard-coded zapret-style
  chains** (`ncp_dpi_zapret.cpp:315-597`) grouped into 8 profiles, but backs them
  with 15+ native techniques, a Geneva genetic-algorithm evolver, TLS fingerprinting,
  and ECH that zapretgui/winws does not attempt.
- **The import bridge is real but syntax-dated.** Dynam already has
  `ncp import-zapret` (`ncp_zapret_import.cpp`, `src/cli/main.cpp:4455`) that
  parses classic zapret `--dpi-desync=` flags into Dynam chains. It does **not**
  parse zapretgui's winws2 `--lua-desync=` DSL, so it cannot ingest the modern
  200+ catalog as-is.
- **Auto-selection philosophies differ.** zapretgui has a live "orchestrator"
  that cycles prebuilt strategies against real sites. Dynam has a more formal
  self-learning autopilot (`autopilot.cpp`, `preset_autopilot.cpp`) with escalation
  rungs and a Geneva GA, but driven by its own TLS-probe BlockChecker, not a 200+
  strategy sweep.
- **Licensing + platform divergence.** Dynam is **AGPLv3** (copyleft, network use
  triggers source obligations); zapretgui is **MIT**. Dynam is cross-platform C++
  (`#ifdef _WIN32` branches throughout, e.g. `ncp_blockcheck.cpp:15-45`); zapretgui
  is Windows-10/11-only Python. MIT→AGPL ingestion of catalog *data* is generally
  fine; copying GPL'd winws behavior is not the model here.

---

## 2. Capability matrix

| Feature | Zapret 2 GUI | Dynam | Notes / Gap |
|---|---|---|---|
| **Strategy count / model** | 200+ curated named strategies (preset→profile→strategy/desync model from bol-van) in `.txt` catalogs | ~13 built-in chains → 8 profiles (`ncp_dpi_zapret.cpp:315`, `:693`) + unlimited via `import-zapret` + Geneva-evolved | zapretgui breadth is far larger; Dynam model is chains/profiles + runtime evolution |
| **Kernel / data path** | Launches external `winws.exe` + `winws2.exe` (bol-van zapret, WinDivert) | Own engine: WinDivert packet mode + raw sockets + proxy mode (`ncp_blockcheck.cpp:15`, README:307 "packet-mode (WinDivert)") | Dynam does not depend on/launch winws; it reimplements desync natively |
| **Preset / profile system** | Documented presets + profiles (wiki.zapret.moe) | `ZapretProfileId` enum + `get_zapret_profile*` (`ncp_dpi_zapret.cpp:607-697`); DPI presets TSPU/GFW/Iran/… (`DPI_ADVANCED_GUIDE.md:420-490`) | Both have presets; zapretgui's are community-sourced, Dynam's are code-defined |
| **Lua / scripted strategies** | Yes — winws2 `--lua-desync=…` DSL, custom Lua strategies | **No Lua.** Chains are C++ structs; importer handles `--dpi-desync=` only (`ncp_zapret_import.cpp:303`) | **Gap:** Dynam can't parse/run `--lua-desync` or Lua blobs |
| **Live orchestrator / auto-select** | "Orchestrator": live cycling of prebuilt strategies | `PresetAutoPilot` + `AutoPilot` escalation rungs + Geneva GA (`preset_autopilot.cpp:76-113`, `autopilot.cpp`); `ncp_orchestrator.cpp` (39 KB) threat-adaptive pipeline | Different mechanism; Dynam probes via TLS BlockChecker, not a 200-strategy sweep |
| **Per-domain hostlist** | GUI-managed domain lists per strategy; hosts-file unblocking | `HostlistMatcher` + cached per-path matcher, wildcard/subdomain (`ncp_hostlist.cpp:14-45`, `ncp_dpi_zapret.cpp:731-860`); `--hostlist`/`-exclude`/`-auto` parsed (`ncp_zapret_import.cpp:463-484`) | Comparable at engine level; Dynam lacks the GUI list editor |
| **QUIC / HTTP-3** | fake-quic, STUN, voice strategies (winws2 `udp.txt`/`voice.txt`) | `build_fake_quic_initial` (`ncp_quic.cpp:7`), QUIC fake chains (`ncp_dpi_zapret.cpp:318-335`, `:481-500`), `ncp_real_quic.cpp`, `ncp_quic_director_adapter.cpp` | Both cover QUIC; parity plausible [unverified at runtime] |
| **IPv6** | Strategies carry `ip6_*` opts (autottl/hopbyhop2) in catalog | `--filter-l3=ipv6` parsed (`ncp_zapret_import.cpp:278-284`); DoH AAAA/`AF_INET6` (`doh.cpp:878`, `:1416`); hopbyhop phase1 (`ncp_dpi_zapret.cpp:43`) | **Partial gap:** importer accepts `ipv6` filter but drops `ip6_autottl`/`ip6_ttl`/`ip6_hopbyhop2` per-chain opts |
| **ALT modes (ALT1..ALT12)** | All `general ALT1`–`ALT12` supported | Not modeled as named ALT presets; equivalent desync combos achievable manually | **Gap:** no ALT naming/mapping; would come via catalog import |
| **DNS handling** | Custom DNS servers against ISP DNS spoofing; hosts-file edits | DoH client (`doh.cpp`), DNS-leak prevention (`ncp_dns_leak_prevention.cpp`), stego-DNS (`ncp_stegodns.cpp`) | Dynam has encrypted DNS but no built-in OS DNS-config / hosts-file editor |
| **GUI** | Primary deliverable: full tray/desktop GUI launcher | Flask web GUI + Qt6 `ncp-qt.exe` (README:70-72, :307) with bypass controls, zapret import w/ preview | Both have GUIs; zapretgui's is more strategy-catalog-centric |
| **Licensing** | **MIT** | **AGPLv3** (README:645) + per-feature license keys (`license.cpp`) | Copyleft divergence; see §6 |
| **Cross-platform** | Windows 10/11 only (Python) | C++17, Windows + POSIX branches throughout (`ncp_blockcheck.cpp:28-45`) | Dynam is portable; zapretgui is not |
| **Block "Max" messenger install** | Yes (explicit feature) | No equivalent feature | **Gap:** OS-level app-install blocking is out of Dynam's scope |
| **Block-check diagnostics** | Built-in blockcheck + winws log analyzer (`src/blockcheck`, `src/winws_log_analyzer`) | `BlockChecker` TLS probe (`ncp_blockcheck.cpp`); optional wrapper around upstream zapret blockcheck (`docs/ZAPRET_EVIDENCE.md`) | Comparable; Dynam's is a safety-gated lab wrapper |

---

## 3. What Zapret 2 GUI has that Dynam lacks (actionable)

1. **`--lua-desync=` DSL parser.** The modern winws2 catalog is written in a
   colon-delimited Lua-strategy DSL, e.g.
   `--lua-desync=fakemultisplit:fake_blob=tls_google:pos=1,midsld:seqovl=211:seqovl_pattern=tls_google`
   and multi-line stacks of `send`/`syndata`/`fake`/`multisplit`/`multidisorder`.
   Dynam's importer only recognizes classic `--dpi-desync=` flags and emits
   "unsupported option" for anything else (`ncp_zapret_import.cpp:524-527`).
   *Impl note:* add a sibling parser in `ncp_zapret_import.cpp` that tokenizes on
   `:` and maps verbs (`fake`, `multisplit`, `multidisorder`, `fakedsplit`,
   `fakeddisorder`, `hostfakesplit`, `syndata`, `send`, `pktmod`) + kv params
   (`blob`, `pos`, `seqovl`, `seqovl_pattern`, `tcp_ack`, `tcp_ts`, `tcp_md5`,
   `ip_ttl`, `ip6_ttl`, `ip_autottl`, `ip6_autottl`, `tls_mod`, `repeats`,
   `fake_count`, `fake_all`) onto `ZapretChain`.

2. **A 200+ strategy catalog.** zapretgui ships curated per-ISP/per-service
   strategies (MGTS, Rostelecom, Megafon, Discord Voice, YouTube, Battlefield,
   etc.). Dynam has 13 chains. *Impl note:* once the DSL parser (#1) exists, a
   `ncp_reference_profile_catalog.cpp` extension could store imported strategies
   as named profiles.

3. **Named `general ALT1..ALT12` presets.** Users expect these names. *Impl note:*
   map the catalog's `alt1_161`/`general_alt11_191`/… entries to Dynam profile
   IDs in `ncp_dpi_zapret.cpp:680` (`get_zapret_profile_by_name`).

4. **Named TLS fake-blob library (`tls_google`, `tls_max`, `tls7`, `stun_pat`,
   `dtls_w3`, …).** Strategies reference prebuilt ClientHello/pattern blobs.
   Dynam generates fakes procedurally (`ncp_quic.cpp`, TLS fingerprint module)
   but has no named-blob registry keyed by the catalog names. *Impl note:* add a
   blob table consumed by `chain_to_overrides` (`ncp_dpi_zapret.cpp:867`).

5. **`seqovl_pattern` + `tcp_ts`/`tcp_ack` offset semantics.** The catalog uses
   seqovl *with a named pattern* and signed TCP ack/ts deltas. Dynam parses
   `--dpi-desync-split-seqovl` as a plain int (`ncp_zapret_import.cpp:315-319`)
   and has no `seqovl_pattern` or `tcp_ack=-66000`-style field. *Impl note:*
   extend `ZapretChain` + parser + `chain_to_cmdline` (`ncp_dpi_zapret.cpp:132`).

6. **hosts-file unblocking (ChatGPT/Gemini/Notion) + custom OS DNS.** zapretgui
   edits the Windows `hosts` file and sets system DNS. Dynam does encrypted DNS
   client-side only. *Impl note:* new module (e.g. `ncp_hostsfile.cpp`) + a DNS
   OS-config helper; not present today.

7. **Block install of the "Max" messenger.** No Dynam analog; OS-policy feature
   out of current scope.

8. **winws log analyzer + GUI per-strategy list editor.** zapretgui parses winws
   logs and lets users edit domain lists per strategy in the GUI. Dynam's GUIs
   expose hostlist/ipset controls (README:307) but no winws-log analysis (Dynam
   has no winws).

---

## 4. What Dynam has that Zapret 2 GUI lacks (differentiators)

- **Self-contained native engine** — reimplements desync (fake/split/disorder/
  overlap, TTL fakes, bad checksum) in C++ (`ncp_desync_confuse.cpp:40-66`,
  `ncp_dpi.cpp` ~149 KB, `dpi_advanced.cpp` ~54 KB) rather than shelling out to
  winws.
- **Geneva genetic-algorithm strategy evolution** (`ncp_geneva_engine.cpp`,
  `ncp_geneva_ga.cpp`, wired into autopilot at `preset_autopilot.cpp:117`) — can
  *discover* new desync strategies, not just cycle a fixed list.
- **TLS fingerprinting (JA3/JA4, Chrome/Firefox/Safari/Edge) + per-connection
  rotation** (`tls_fingerprint.cpp`, `DPI_ADVANCED_GUIDE.md:106-163`). winws does
  not synthesize browser-accurate ClientHellos.
- **ECH (Encrypted Client Hello) via HPKE** (`ncp_ech*.cpp`,
  `DPI_ADVANCED_GUIDE.md:167-209`).
- **Full alternative transport/anti-censorship stack** absent from a zapret
  launcher: XTLS-Reality (`ncp_reality.cpp`), Tor/I2P (`ncp_tor_manager.cpp`,
  `i2p.cpp`), WebSocket tunnel (`ncp_ws_tunnel.cpp`), TURN (`ncp_turn_*.cpp`),
  port-hopping/knocking/SPA (`ncp_porthop.cpp`, `ncp_port_knock.cpp`, `ncp_spa.cpp`),
  Fog mesh relay (`ncp_fog.cpp`), eBPF/XDP filtering (`ncp_xdp.cpp`).
- **ML-classifier evasion & traffic shaping**: adversarial padding
  (`ncp_adversarial.cpp`), flow/burst/volume/entropy shaping
  (`ncp_flow_shaper.cpp`, `ncp_burst_morpher.cpp`, `ncp_volume_normalizer.cpp`,
  `ncp_entropy_masking.cpp`), probe resistance (`ncp_probe_resist.cpp`).
- **Cross-platform** (Linux/POSIX + Windows) vs. Windows-only Python.
- **Threat-adaptive orchestrator** with formal escalation levels
  direct→preset→augmented→geneva (`preset_autopilot.cpp:66-113`).

---

## 5. Import recommendations — `ncp import-zapret`

**How far it goes today** (`ncp_zapret_import.cpp`, CLI `src/cli/main.cpp:4455`):

- Shell-tokenizes a zapret command line (`zapret_tokenize`, `:13`) and walks argv
  (`parse_zapret_argv`, `:218`), splitting on `--new` into multiple chains.
- Understands the **classic zapret flag set**: `--filter-tcp/-udp/-l3/-l7`,
  `--dpi-desync=` phase names (synack/syndata/fake/rst/multisplit/multidisorder/
  fakedsplit/fakeddisorder/hostfakesplit/ipfrag/udplen/tamper, `:115-150`),
  `--dpi-desync-split-pos` incl. markers (method/host/sld/midsld/sniext, `:68-97`),
  `-split-seqovl`, `-fooling` (ts/badseq/badsum/md5sig/datanoack/hopbyhop, `:99-113`),
  `-repeats`, `-ttl`, `-autottl`, fake types (tls/http/quic/wireguard/dht/discord/
  stun/syndata/unknown/hex, `:353-381`), `fake-tls-mod` (rnd/rndsni/dupsid/
  padencap/sni=, `:382-395`), `-ipid`, `-dup*`, `-udplen-*`, `-tcp-flags`,
  `-start`/`-cutoff` conditions, `--hostlist*`, `--ipset*`, `--wssize*`,
  `--wf-tcp/-udp/-raw`, `--ssid-filter`.
- Emits JSON (`zapret_profile_to_json`, `:546`) with per-chain cmdline
  round-trip (`chain_to_cmdline`, `ncp_dpi_zapret.cpp:132`), plus warnings/errors.
- **Verdict:** a solid, faithful importer for **Zapret 1 / classic winws**
  command lines. It is the right extension point.

**What to extend to ingest zapretgui's 200+ (winws2) set:**

1. **Add a `--lua-desync=` DSL front-end** (biggest gap). zapretgui's winws2
   catalog entries are *not* `--dpi-desync` flags; they are colon-delimited Lua
   strategy strings, often stacked over multiple lines. The current parser routes
   these to "unsupported option" (`:524`). Add `parse_lua_desync_strategy()`
   that:
   - splits each `--lua-desync=` line into `verb` + `k[=v]` params on `:`;
   - maps verbs onto existing `ZDesyncPhase*`/`ZFakeType` where possible
     (`fake`→phase1 FAKE+fake_type, `multisplit`→phase2 MULTISPLIT,
     `multidisorder`→MULTIDISORDER, `fakedsplit`/`fakeddisorder`/`hostfakesplit`
     already exist as enums in `ncp_dpi_zapret.hpp`);
   - treats stacked lines as an ordered chain list (the `send`/`syndata`/`fake`/
     `split` sequence), which Dynam can model as multiple chains or an ordered
     action list.

2. **Parse the INI-style catalog header** (`[id]`, `name=`, `old_name=`,
   `author=`, `label=`, `description=`, `blobs=`). Store `name`/`label` into
   `ZapretProfile.label`/`description` (`ncp_dpi_zapret.cpp:609-615`) so imported
   strategies are human-selectable and preserve the `recommended`/`experimental`/
   `game` labels.

3. **Add missing kv params to `ZapretChain`** and the serializer: `tcp_ack`
   (signed), `tcp_ts`/`tcp_ts_up`, `ip_ttl`/`ip6_ttl`, `ip_autottl`/`ip6_autottl`
   (signed delta + range), `ip6_hopbyhop2`, `seqovl_pattern`, `fake_count`,
   `fake_all`, `payload=`. Several have no `ZapretChain` field yet.

4. **Build a named fake-blob registry** keyed by catalog names (`tls_google`,
   `tls_max`, `tls7`…`tls18`, `stun_pat`, `dtls_w3`, `fake_default_tls`,
   `fake_default_http`, `0x…` hex) so `fake_blob=`/`seqovl_pattern=` resolve.
   Feed into `chain_to_overrides` (`:867`).

5. **Bulk-import mode.** Accept a whole catalog `.txt` (many `[sections]`) and
   produce an array of named profiles, not just one. Today `--file` reads one
   command line (`src/cli/main.cpp:4463-4473`).

6. **Round-trip test harness.** Extend the existing import test path to assert
   parse→JSON→(re)cmdline stability on a sample of the 200+ entries, flagging
   lossy fields as warnings (parser already accumulates `res.warnings`).

---

## 6. Honest caveats

- **Licensing difference is material.** Dynam is **AGPLv3** (README:645) —
  strong copyleft that extends to network-served use. zapretgui is **MIT**.
  Importing zapretgui's **strategy data/catalog** (facts/parameters) into an AGPL
  project is generally unproblematic, and MIT→AGPL code reuse is one-directional
  compatible, but the reverse (AGPL code into MIT) is not. zapretgui itself
  *launches* bol-van's zapret/winws, whose own license governs that binary; Dynam
  does not bundle or launch winws. Any catalog ingestion should attribute authors
  (`author=` fields such as Flowseal, bol-van, hz, loop-uh, Dronatar) and respect
  upstream terms. This is an engineering note, not legal advice.
- **Nothing here was runtime-tested.** No compiler, no git, no network bypass
  tests were run. Dynam capabilities are asserted from source and docs only;
  QUIC/IPv6 "parity" claims are `[unverified]` at runtime. zapretgui behavior is
  inferred from its README and catalog text, not from executing it.
- **zapretgui is a moving target.** It mirrors a self-hosted Forgejo repo
  (4,000+ commits) and the catalog grows continuously; any importer will need
  periodic re-sync. The strategy count ("200+") is the project's own claim.
- **Dynam's zapret chains are hard-coded for a point-in-time zapret v72.x
  config** (`ncp_dpi_zapret.cpp:295`) and may lag current TSPU behavior.
