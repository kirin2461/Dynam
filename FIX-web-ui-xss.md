# Fix: stored XSS in the web control panel (W-01, W-02)

**Date**: 2026-11-16
**Files changed**: `web/static/js/app.js`
**Source**: `plan.md` §7.1, W-01 and W-02
**Status**: Fixed. **Checked by reading only** — no Python or Node on the build
machine, so the panel was not run.

---

## Summary

The panel built table rows and monitor events as HTML strings assigned to
`innerHTML`, interpolating server-supplied values without escaping. The worst
is `ev.host` in the live monitor feed: it comes from the SOCKS CONNECT request
(`src/core/src/ncp_proxy.cpp:1325`), so **any client of the local proxy can set
it to arbitrary bytes**. The C++ side only JSON-escapes it, which does not stop
HTML.

A proxy client sending a host like `<img src=x onerror=…>` gets script running
in the panel. The page carries the API token in `<meta name="ncp-token">`, so
that script can call every `/api/*` route — start processes, install updates,
change config. A proxy client could take over the control panel.

## The change

Every interpolated value in an `innerHTML` template literal now goes through the
existing `escapeHtml()` helper (`app.js:1297`).

Before (monitor feed, W-01):

```js
div.innerHTML = `… → <b>${ev.host}</b>:${ev.port} <span class="badge">${ev.strategy || 'base'}</span>`;
div.innerHTML = `… ⏱ <b>${ev.host}</b> → <span style="color:${c}">${ev.result}</span>`;
```

After: `ev.host`, `ev.port`, `ev.strategy`, `ev.result` escaped. Colours come only
from the fixed `colors` map, never from server data.

W-02 sites:

| Area | Fields now escaped |
|---|---|
| E2E sessions | `s.id`, `s.peer`, `s.cipher`, `s.msg_count`, `s.status` |
| I2P tunnels | `t.id`, `t.type`, `t.hops`, `t.destination`, `t.status` |
| Log lines | `entry.ts`, `entry.level` (`entry.msg` already was) |
| Module rows, presets, interfaces | `m.label`, `op.id`, `p.id`, `icon`, `i.name`, `i.ips` |

Values in `data-*` attributes are escaped too — an unescaped `"` would break out
of the attribute.

## Verification

```
grep -nE '\$\{[a-zA-Z_][a-zA-Z0-9_.\[\]]*\}' web/static/js/app.js \
  | grep -vE "escapeHtml|_esc\("
```

Two hits remain, neither an HTML sink:

| Line | Code | Why safe |
|---|---|---|
| 72 | `` document.querySelector(`[data-nav="${id}"]`) `` | CSS selector; `id` is a fixed nav name |
| 264 | `` parts.push(`Последнее переключение: ${from} → ${to} …`) `` | assigned to `el.title`, a text property |

## Limitations

- **Not run.** The browser test from `plan.md` §7.4 (proxy event with
  `host = "<img src=x onerror=alert(1)>"` must render as text) is not written.
- The grep matches only `${name}` / `${a.b}`. Expressions like `${cond ? a : b}`
  were checked by eye in the diff.
- Nothing prevents a future unescaped `innerHTML`; the CI grep proposed in
  `plan.md` §7.1 remains a follow-up.
- Only `app.js` was reviewed. `charts.js`, `help.js` and enterprise JS were not.
