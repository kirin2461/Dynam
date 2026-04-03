/**
 * NCP Web Interface — Main Application Logic
 * Handles navigation, API calls, state management, and UI updates.
 */

// ─── API Base URL ─────────────────────────────────────────────────────────

const API_BASE = (() => {
  const meta = document.querySelector('meta[name="api-base"]');
  return meta ? meta.content.replace(/\/+$/, '') : '';
})();

async function apiFetch(path, opts = {}) {
  try {
    const resp = await fetch(API_BASE + path, {
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      ...opts,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      // License gate: 403 with license_required flag
      if (resp.status === 403 && err.license_required) {
        const msg = err.upgrade_needed
          ? (err.error || 'Модуль недоступен') + ' — обновите план'
          : 'Лицензия не активирована — откройте раздел «Лицензия»';
        showToast(msg, 'error', 5000);
        // Auto-navigate to the license section
        navigateTo('license');
        throw new Error(msg);
      }
      throw new Error(err.error || resp.statusText);
    }
    return resp.json();
  } catch (e) {
    showToast(e.message || 'Ошибка сети', 'error');
    throw e;
  }
}

// ─── Toast Notifications ──────────────────────────────────────────────────

function showToast(msg, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast toast--${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    el.style.transition = 'all 300ms ease';
    setTimeout(() => el.remove(), 310);
  }, duration);
}

// ─── Navigation ───────────────────────────────────────────────────────────

let currentSection = 'overview';

function navigateTo(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar__item').forEach(i => i.classList.remove('active'));
  const section = document.getElementById('sec-' + id);
  if (section) section.classList.add('active');
  const navItem = document.querySelector(`[data-nav="${id}"]`);
  if (navItem) navItem.classList.add('active');
  currentSection = id;
  // Close mobile sidebar
  document.querySelector('.sidebar')?.classList.remove('open');
  // Lazy-load section data
  loadSectionData(id);
}

function loadSectionData(id) {
  switch (id) {
    case 'dpi':       loadDpiOperators(); loadZapretProfiles(); break;
    case 'network':   loadNetworkInterfaces(); break;
    case 'e2e':       loadE2ESessions(); break;
    case 'i2p':       loadI2PTunnels(); break;
    case 'license':   loadLicense(); break;
    case 'logs':      loadLogs(); break;
    case 'settings':  loadSettings(); break;
    case 'geneva':    refreshGenevaStatus(); break;
    case 'mimicry':   loadConfig(); break;
    case 'pipeline':  loadModuleStats(); break;
    case 'antiml':    loadModuleStats(); break;
    case 'covert':    loadModuleStats(); break;
    case 'transport': loadModuleStats(); break;
    case 'telegram':  loadTgProxies(); break;
  }
}

// ─── State ────────────────────────────────────────────────────────────────

const appState = {
  running: false,
  uptime: '00:00:00',
  stats: {},
  config: {},
  wsConnected: false,
  logBuffer: [],
  logFilter: 'ALL',
  logSearch: '',
};

// ─── Status Polling ───────────────────────────────────────────────────────

async function refreshStatus() {
  try {
    const data = await apiFetch('/api/status');
    appState.running = data.running;
    appState.uptime = data.uptime;
    updateStatusUI();
  } catch (_) {}
}

function updateStatusUI() {
  const running = appState.running;
  const dot = document.getElementById('header-dot');
  const connectBtn = document.getElementById('btn-connect');
  const heroRing = document.getElementById('status-ring');
  const heroLabel = document.getElementById('status-label');
  const heroSub = document.getElementById('status-sub');
  const uptimeEl = document.getElementById('uptime-value');

  if (dot) dot.className = 'status-dot' + (running ? ' running' : '');

  if (connectBtn) {
    connectBtn.className = 'btn-connect' + (running ? ' active' : '');
    connectBtn.innerHTML = running
      ? `<span class="status-dot running"></span> Отключить`
      : `<span class="status-dot"></span> Подключить`;
  }

  if (heroRing) {
    heroRing.className = 'status-hero__ring ' + (running ? 'running' : 'stopped');
  }
  if (heroLabel) {
    heroLabel.textContent = running ? 'ЗАЩИТА АКТИВНА' : 'НЕ ПОДКЛЮЧЕНО';
    heroLabel.style.color = running ? 'var(--green)' : 'var(--red)';
  }
  if (heroSub) {
    if (running) {
      const opLabel = OPERATOR_LABELS[appState.config?.dpi_preset] || appState.config?.dpi_preset || '';
      heroSub.textContent = `Стратегия: ${appState.config?.strategy || '—'}${opLabel ? ' · ' + opLabel : ''}`;
    } else {
      heroSub.textContent = 'Нажмите «Подключить» для запуска';
    }
  }
  if (uptimeEl) uptimeEl.textContent = appState.uptime;

  // Statusbar uptime
  const sbUptime = document.getElementById('sb-uptime');
  if (sbUptime) sbUptime.textContent = running ? appState.uptime : '—';
}

// ─── Connect / Disconnect ─────────────────────────────────────────────────

document.getElementById('btn-connect')?.addEventListener('click', toggleConnection);

async function toggleConnection() {
  const btn = document.getElementById('btn-connect');
  if (btn) btn.disabled = true;
  try {
    if (appState.running) {
      await apiFetch('/api/stop', { method: 'POST' });
      showToast('NCP остановлен', 'warn');
    } else {
      await apiFetch('/api/start', { method: 'POST' });
      showToast('NCP запущен — защита активна', 'success');
    }
    await refreshStatus();
  } catch (_) {}
  if (btn) btn.disabled = false;
}

// ─── Stats Updates ────────────────────────────────────────────────────────

function applyStats(data) {
  appState.stats = { ...appState.stats, ...data };
  if (data.uptime) appState.uptime = data.uptime;

  // KPI cards
  setEl('kpi-packets', formatNumber(data.packets_processed));
  setEl('kpi-dpi-blocks', formatNumber(data.dpi_blocks_avoided));
  setEl('kpi-transferred', formatBytes(data.bytes_recv + data.bytes_sent));
  setEl('kpi-connections', data.active_connections ?? '—');
  setEl('kpi-dpi-events', formatNumber(data.dpi_events));

  // Status bar
  setEl('sb-up', formatBytes(data.speed_up) + '/s');
  setEl('sb-down', formatBytes(data.speed_down) + '/s');
  setEl('sb-dpi', formatNumber(data.dpi_events));
  setEl('sb-pkts', formatNumber(data.packets_processed));
  if (data.uptime) setEl('sb-uptime', data.uptime);

  // Charts
  updateTrafficChart(data.speed_up || 0, data.speed_down || 0);
}

// ─── Module Stats ─────────────────────────────────────────────────────────

async function loadModuleStats() {
  try {
    const data = await apiFetch('/api/modules');
    applyModuleStats(data);
  } catch (_) {}
}

function applyModuleStats(data) {
  if (!data) return;

  // ── Pipeline section KPIs ──────────────────────────────────────────────
  setEl('kpi-mod-pipeline-throughput',     formatNumber(data.pipeline_throughput));
  setEl('kpi-mod-pipeline-queue-usage',    data.pipeline_queue_usage != null ? data.pipeline_queue_usage + '%' : '—');
  setEl('kpi-mod-pipeline-drops',          formatNumber(data.pipeline_drops));
  setEl('kpi-mod-dns-queries-intercepted', formatNumber(data.dns_queries_intercepted));

  // Pipeline inline stats
  setEl('mod-pipeline-throughput',  formatNumber(data.pipeline_throughput));
  setEl('mod-pipeline-queue',       data.pipeline_queue_usage != null ? data.pipeline_queue_usage + '%' : '—');
  setEl('mod-pipeline-drops',       formatNumber(data.pipeline_drops));
  setEl('mod-dns-blocked',          formatNumber(data.dns_leaks_blocked));
  setEl('mod-dns-intercepted',      formatNumber(data.dns_queries_intercepted));
  setEl('mod-sessions-fragmented',  formatNumber(data.sessions_fragmented));
  setEl('mod-fragments-created',    formatNumber(data.fragments_created));
  setEl('mod-correlations-checked', formatNumber(data.correlations_checked));
  setEl('mod-anomalies-fixed',      formatNumber(data.anomalies_fixed));

  // Update pipeline chart if available
  if (typeof updatePipelineChart === 'function') {
    updatePipelineChart(data.pipeline_throughput || 0);
  }

  // ── Anti-ML section KPIs ──────────────────────────────────────────────
  setEl('kpi-mod-rtt-current-ms',          data.rtt_current_ms != null ? data.rtt_current_ms + ' мс' : '—');
  setEl('kpi-mod-volume-padding-bytes',    formatBytes(data.volume_padding_bytes));
  setEl('kpi-mod-cloak-actions-emulated',  formatNumber(data.cloak_actions_emulated));
  setEl('kpi-mod-time-correlations-broken', formatNumber(data.time_correlations_broken));

  // Anti-ML inline stats
  setEl('mod-rtt-current',          data.rtt_current_ms != null ? data.rtt_current_ms + ' мс' : '—');
  setEl('mod-rtt-delayed',          formatNumber(data.rtt_packets_delayed));
  setEl('mod-volume-padding',       formatBytes(data.volume_padding_bytes));
  setEl('mod-volume-flows',         formatNumber(data.volume_normalized_flows));
  setEl('mod-cloak-actions',        formatNumber(data.cloak_actions_emulated));
  setEl('mod-cloak-patterns',       formatNumber(data.cloak_patterns_matched));
  setEl('mod-time-broken',          formatNumber(data.time_correlations_broken));
  setEl('mod-time-chaff',           formatNumber(data.time_chaff_packets));

  // ── Covert section KPIs ───────────────────────────────────────────────
  setEl('kpi-mod-covert-bytes-sent', formatBytes(data.covert_bytes_sent));
  setEl('kpi-mod-covert-bytes-recv', formatBytes(data.covert_bytes_recv));
  setEl('kpi-mod-wf-packets-padded', formatNumber(data.wf_packets_padded));
  setEl('kpi-mod-self-test-score',   data.self_test_score != null ? data.self_test_score + '/100' : '—');

  // Covert inline stats
  setEl('mod-covert-sent',          formatBytes(data.covert_bytes_sent));
  setEl('mod-covert-recv',          formatBytes(data.covert_bytes_recv));
  setEl('mod-channels-active',      formatNumber(data.covert_channels_active));
  setEl('mod-wf-padded',            formatNumber(data.wf_packets_padded));
  setEl('mod-wf-overhead',          formatBytes(data.wf_overhead_bytes));
  setEl('mod-self-test-score-badge', data.self_test_score != null ? data.self_test_score + '/100' : '—');
  setEl('mod-self-test-issues',     data.self_test_issues != null ? data.self_test_issues : '—');
  setEl('mod-selftest-last',        data.self_test_last_run || '—');

  // Self-test history
  if (data.self_test_history) {
    renderSelfTestHistory(data.self_test_history);
  }

  // ── Transport section KPIs ────────────────────────────────────────────
  setEl('kpi-mod-current-protocol',      data.rotation_current_protocol || '—');
  setEl('kpi-mod-rotations-completed',   formatNumber(data.rotations_completed));
  setEl('kpi-mod-as-routes-diverted',    formatNumber(data.as_routes_diverted));
  setEl('kpi-mod-geo-apparent-location', data.geo_apparent_location || '—');

  // Transport inline stats
  setEl('mod-current-protocol',    data.rotation_current_protocol || '—');
  setEl('mod-rotations',           formatNumber(data.rotations_completed));
  setEl('mod-as-diverted',         formatNumber(data.as_routes_diverted));
  setEl('mod-as-current-path',     data.as_current_path || '—');
  setEl('mod-geo-apparent-location', data.geo_apparent_location || '—');
  setEl('mod-geo-hops-active',     data.geo_hops_active != null ? data.geo_hops_active : '—');

  // ── Overview subsystems update ────────────────────────────────────────
  updateOverviewSubsystems(data);
}

function updateOverviewSubsystems(data) {
  const el = document.getElementById('active-techniques-display');
  if (!el) return;

  // Build module status entries to append/update
  const modules = [
    { id: 'subsys-pipeline',  label: 'Пайплайн',        active: data.pipeline_throughput > 0 },
    { id: 'subsys-antiml',    label: 'Анти-ML',          active: data.time_correlations_broken > 0 || data.rtt_current_ms > 0 },
    { id: 'subsys-covert',    label: 'Скрытые каналы',   active: data.covert_channels_active > 0 },
    { id: 'subsys-transport', label: 'Транспорт',        active: !!data.rotation_current_protocol },
  ];

  modules.forEach(m => {
    let row = document.getElementById(m.id);
    if (!row) {
      row = document.createElement('div');
      row.id = m.id;
      row.className = 'toggle-wrap';
      row.style.padding = 'var(--sp-2) 0';
      el.appendChild(row);
    }
    row.innerHTML = `
      <span class="toggle-name">${m.label}</span>
      <span class="badge badge--${m.active ? 'active' : 'inactive'}">${m.active ? 'Активен' : 'Неактивен'}</span>
    `;
  });
}

// ─── Log Handler ─────────────────────────────────────────────────────────

function onLogEntry(entry) {
  appState.logBuffer.push(entry);
  if (appState.logBuffer.length > 1000) appState.logBuffer.shift();
  if (currentSection === 'logs') appendLogEntry(entry);
}

function appendLogEntry(entry) {
  const viewer = document.getElementById('log-viewer');
  if (!viewer) return;
  if (appState.logFilter !== 'ALL' && entry.level !== appState.logFilter) return;
  if (appState.logSearch && !entry.msg.toLowerCase().includes(appState.logSearch)) return;

  const el = document.createElement('div');
  el.className = 'log-entry';
  el.innerHTML = `<span class="log-ts">${entry.ts}</span><span class="log-level log-level--${entry.level}">${entry.level.padEnd(5)}</span><span class="log-msg">${escapeHtml(entry.msg)}</span>`;
  viewer.appendChild(el);

  // Auto-scroll
  if (document.getElementById('log-autoscroll')?.checked !== false) {
    viewer.scrollTop = viewer.scrollHeight;
  }
}

async function loadLogs() {
  const viewer = document.getElementById('log-viewer');
  if (!viewer) return;
  viewer.innerHTML = '';
  try {
    const logs = await apiFetch(`/api/logs?n=200`);
    logs.forEach(appendLogEntry);
  } catch (_) {}
}

// ─── Config ───────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    appState.config = await apiFetch('/api/config');
    applyConfigToUI();
  } catch (_) {}
}

function applyConfigToUI() {
  const c = appState.config;

  // ── Existing toggles ──────────────────────────────────────────────────
  setToggle('toggle-tcp-frag', c.tcp_fragment);
  setToggle('toggle-tls-split', c.tls_split);
  setToggle('toggle-ttl-manip', c.ttl_manip);
  setToggle('toggle-fake-pkt', c.fake_packets);
  setToggle('toggle-pkt-disorder', c.pkt_disorder);
  setToggle('toggle-sni-spoof', c.sni_spoof);
  setToggle('toggle-ech', c.ech_enabled);
  setToggle('toggle-paranoid', c.paranoid_mode);
  setToggle('toggle-auto-rotate', c.auto_rotate);
  setToggle('toggle-antiforensics', c.antiforensics);
  setToggle('toggle-autostart', c.autostart);
  setToggle('toggle-burst-morph', c.burst_morphing);
  setToggle('toggle-postquantum', c.postquantum);
  setToggle('toggle-i2p', c.i2p_enabled);
  setToggle('toggle-garlic', c.garlic_routing);
  setToggle('toggle-port-knock', c.port_knocking);

  // ── New module toggles ────────────────────────────────────────────────
  setToggle('toggle-pipeline-enabled',       c.pipeline_enabled);
  setToggle('toggle-dns-leak-prevention',    c.dns_leak_prevention);
  setToggle('toggle-session-fragmenter',     c.session_fragmenter);
  setToggle('toggle-cross-layer-enabled',    c.cross_layer_enabled);
  setToggle('toggle-rtt-equalizer',          c.rtt_equalizer);
  setToggle('toggle-volume-normalizer',      c.volume_normalizer);
  setToggle('toggle-behavioral-cloak',       c.behavioral_cloak);
  setToggle('toggle-cloak-human-sim',        c.cloak_human_sim);
  setToggle('toggle-time-correlation-breaker', c.time_correlation_breaker);
  setToggle('toggle-covert-channel',         c.covert_channel);
  setToggle('toggle-wf-defense',             c.wf_defense);
  setToggle('toggle-self-test-enabled',      c.self_test_enabled);
  setToggle('toggle-protocol-rotation',      c.protocol_rotation);
  setToggle('toggle-as-aware-routing',       c.as_aware_routing);
  setToggle('toggle-as-prefer-diversity',    c.as_prefer_diversity);
  setToggle('toggle-geo-obfuscator',         c.geo_obfuscator);

  // ── Existing selects / inputs ─────────────────────────────────────────
  setVal('sel-interface', c.interface);
  setVal('sel-doh', c.doh_provider);
  setVal('inp-doh-custom', c.doh_custom);
  setVal('sel-proxy-type', c.proxy_type);
  setVal('inp-proxy-host', c.proxy_host);
  setVal('inp-proxy-port', c.proxy_port);
  setVal('sel-mimic', c.mimic_protocol);
  setVal('sel-tls-fp', c.tls_fingerprint);
  setVal('sel-flow', c.flow_profile);
  setVal('inp-i2p-host', c.i2p_sam_host);
  setVal('inp-i2p-port', c.i2p_sam_port);
  setVal('inp-rotate-interval', c.rotate_interval);
  setVal('sel-language', c.language);

  // ── New module selects / inputs ───────────────────────────────────────
  setVal('sel-dns-leak-mode',       c.dns_leak_mode);
  setVal('inp-dns-leak-whitelist',  c.dns_leak_whitelist);
  setVal('sel-session-frag-strategy', c.session_frag_strategy);
  setVal('sel-cross-layer-strictness', c.cross_layer_strictness);
  setVal('sel-volume-padding-mode', c.volume_padding_mode);
  setVal('sel-cloak-profile',       c.cloak_profile);
  setVal('sel-time-break-mode',     c.time_break_mode);
  setVal('sel-covert-mode',         c.covert_mode);
  setSlider('range-covert-bandwidth-limit-bps', c.covert_bandwidth_limit_bps, 'val-covert-bandwidth-limit-bps');
  setVal('sel-wf-defense-mode',     c.wf_defense_mode);
  setVal('sel-geo-target-country',  c.geo_target_country);
  setVal('inp-as-blacklist',        c.as_blacklist);

  // ── Existing range sliders ────────────────────────────────────────────
  setSlider('range-fragment', c.fragment_size, 'val-fragment');
  setSlider('range-jitter', c.timing_jitter, 'val-jitter');
  setSlider('range-noise', c.noise_level, 'val-noise');
  setSlider('range-pop', c.geneva_population, 'val-pop');
  setSlider('range-mutation', Math.round((c.geneva_mutation || 0.15) * 100), 'val-mutation');
  setSlider('range-hops', c.i2p_hop_count, 'val-hops');

  // ── New module sliders ────────────────────────────────────────────────
  setSlider('range-pipeline-workers',        c.pipeline_workers,           'val-pipeline-workers');
  setSlider('range-pipeline-queue-size',     c.pipeline_queue_size,        'val-pipeline-queue-size');
  setSlider('range-session-frag-min-segments', c.session_frag_min_segments, 'val-session-frag-min-segments');
  setSlider('range-session-frag-max-segments', c.session_frag_max_segments, 'val-session-frag-max-segments');
  setSlider('range-rtt-target-ms',           c.rtt_target_ms,              'val-rtt-target-ms');
  setSlider('range-rtt-jitter-ms',           c.rtt_jitter_ms,              'val-rtt-jitter-ms');
  setSlider('range-volume-target-kbps',      c.volume_target_kbps,         'val-volume-target-kbps');
  setSlider('range-time-break-max-delay-ms', c.time_break_max_delay_ms,    'val-time-break-max-delay-ms');
  setSlider('range-wf-defense-overhead',     c.wf_defense_overhead,        'val-wf-defense-overhead');
  setSlider('range-self-test-interval-sec',  c.self_test_interval_sec,     'val-self-test-interval-sec');
  setSlider('range-rotation-interval-min',   c.rotation_interval_min,      'val-rotation-interval-min');
  setSlider('range-geo-relay-hops',          c.geo_relay_hops,             'val-geo-relay-hops');
  setSlider('range-covert-bandwidth-limit-bps', c.covert_bandwidth_limit_bps, 'val-covert-bandwidth-limit-bps');

  // ── Preset highlight ──────────────────────────────────────────────────
  document.querySelectorAll('.preset-card[data-preset]').forEach(el => {
    el.classList.toggle('active', el.dataset.preset === c.strategy);
  });

  // ── DPI operator preset highlight ─────────────────────────────────────
  if (c.dpi_preset) {
    selectedOperator = c.dpi_preset;
    if (dpiOperators.length) renderDpiOperators();
  }

  // ── Zapret profile highlight ──────────────────────────────────────────
  if (c.zapret_profile !== undefined) {
    selectedZapretProfile = c.zapret_profile || '';
    if (zapretProfiles.length) renderZapretProfiles();
  }

  // ── Protocol rotation checkboxes ──────────────────────────────────────
  if (c.rotation_protocols) {
    const protos = c.rotation_protocols.split(',').map(p => p.trim());
    document.querySelectorAll('[data-rotation-proto]')?.forEach(el => {
      el.checked = protos.includes(el.dataset.rotationProto);
    });
  }
}

async function saveConfig(partial = {}) {
  const updated = { ...appState.config, ...partial };
  appState.config = updated;
  try {
    await apiFetch('/api/config', { method: 'POST', body: JSON.stringify(updated) });
    showToast('Конфигурация сохранена', 'success');
  } catch (_) {}
}

// ─── DPI Preset ───────────────────────────────────────────────────────────

async function applyPreset(preset) {
  try {
    const data = await apiFetch('/api/dpi/preset', {
      method: 'POST',
      body: JSON.stringify({ preset }),
    });
    appState.config = data.config;
    applyConfigToUI();
    showToast(`Пресет «${preset}» применён`, 'success');
  } catch (_) {}
}

document.querySelectorAll('.preset-card').forEach(el => {
  el.addEventListener('click', () => applyPreset(el.dataset.preset));
});

// ─── DPI Operator / ISP Presets ──────────────────────────────────────────────────

// Icons for each operator
const OPERATOR_ICONS = {
  tspu:    '🏠',
  beeline: '🟡',
  mts:     '🔴',
  megafon: '🟢',
  tele2:   '🟣',
  mobile:  '📱',
  auto:    '🔄',
};

// Russian-friendly labels
const OPERATOR_LABELS = {
  tspu:    'ТСПУ (дом. ИСП)',
  beeline: 'Beeline Mobile',
  mts:     'MTS Mobile',
  megafon: 'Megafon Mobile',
  tele2:   'Tele2 Mobile',
  mobile:  'Универсальный',
  auto:    'Авто-подбор',
};

let dpiOperators = [];
let selectedOperator = 'tspu';

async function loadDpiOperators() {
  try {
    dpiOperators = await apiFetch('/api/dpi/operators');
    selectedOperator = appState.config.dpi_preset || 'tspu';
    renderDpiOperators();
  } catch (_) {}
}

function renderDpiOperators() {
  const grid = document.getElementById('dpi-operator-grid');
  if (!grid) return;

  grid.innerHTML = dpiOperators.map(op => {
    const icon = OPERATOR_ICONS[op.id] || '📶';
    const label = OPERATOR_LABELS[op.id] || op.label;
    const isActive = op.id === selectedOperator;
    return `
      <div class="preset-card${isActive ? ' active' : ''}" data-operator="${escapeHtml(op.id)}" onclick="selectDpiOperator('${escapeHtml(op.id)}')">
        <div class="preset-card__icon">${icon}</div>
        <div class="preset-card__name">${escapeHtml(label)}</div>
        <div class="preset-card__desc" style="font-size:0.65rem;opacity:.7">${escapeHtml(op.description)}</div>
      </div>
    `;
  }).join('');

  // Update badge
  const badge = document.getElementById('dpi-operator-badge');
  const current = dpiOperators.find(o => o.id === selectedOperator);
  if (badge && current) {
    badge.textContent = OPERATOR_LABELS[current.id] || current.label;
  }

  // Update description
  const descEl = document.getElementById('dpi-operator-desc');
  if (descEl && current) {
    descEl.textContent = current.description;
  }
}

async function selectDpiOperator(operatorId) {
  try {
    const data = await apiFetch('/api/dpi/operator', {
      method: 'POST',
      body: JSON.stringify({ operator: operatorId }),
    });
    if (data.ok) {
      selectedOperator = operatorId;
      appState.config.dpi_preset = operatorId;
      renderDpiOperators();

      const label = OPERATOR_LABELS[operatorId] || data.label;
      showToast(`Оператор: ${label}`, 'success');

      // Show restart banner if NCP is running
      const restartBanner = document.getElementById('dpi-operator-restart');
      if (restartBanner) {
        restartBanner.classList.toggle('hidden', !data.needs_restart);
      }
    }
  } catch (_) {}
}

async function restartWithNewPreset() {
  try {
    await apiFetch('/api/stop', { method: 'POST' });
    // Brief delay before restart
    await new Promise(r => setTimeout(r, 500));
    await apiFetch('/api/start', { method: 'POST' });
    showToast('NCP перезапущен с новым пресетом', 'success');
    const restartBanner = document.getElementById('dpi-operator-restart');
    if (restartBanner) restartBanner.classList.add('hidden');
    await refreshStatus();
  } catch (e) {
    showToast('Ошибка перезапуска: ' + (e.message || ''), 'error');
  }
}

// ─── Zapret DPI Config Profiles ─────────────────────────────────────────────────

const ZAPRET_PROFILE_ICONS = {
  zapret_full:    '🔗',
  zapret_general: '🌐',
  zapret_discord: '💬',
  zapret_google:  '▶️',
  zapret_quic:    '⚡',
  zapret_tcp:     '🔌',
  zapret_youtube: '▶️',
  zapret_rublock: '🛡️',
};

let zapretProfiles = [];
let selectedZapretProfile = '';

async function loadZapretProfiles() {
  try {
    zapretProfiles = await apiFetch('/api/dpi/zapret/profiles');
    selectedZapretProfile = appState.config.zapret_profile || '';
    renderZapretProfiles();
  } catch (_) {}
}

function renderZapretProfiles() {
  const grid = document.getElementById('zapret-profile-grid');
  if (!grid) return;

  // Add "disabled" option
  const noneActive = !selectedZapretProfile;
  let html = `
    <div class="preset-card${noneActive ? ' active' : ''}" onclick="selectZapretProfile('')">
      <div class="preset-card__icon">🚫</div>
      <div class="preset-card__name">Выключен</div>
      <div class="preset-card__desc" style="font-size:0.65rem;opacity:.7">Без zapret</div>
    </div>
  `;

  html += zapretProfiles.map(p => {
    const icon = ZAPRET_PROFILE_ICONS[p.id] || p.icon || '📦';
    const isActive = p.id === selectedZapretProfile;
    return `
      <div class="preset-card${isActive ? ' active' : ''}" onclick="selectZapretProfile('${escapeHtml(p.id)}')">
        <div class="preset-card__icon">${icon}</div>
        <div class="preset-card__name" style="font-size:0.75rem">${escapeHtml(p.label)}</div>
        <div class="preset-card__desc" style="font-size:0.6rem;opacity:.7">${p.chains.length} chains</div>
      </div>
    `;
  }).join('');

  grid.innerHTML = html;

  // Badge
  const badge = document.getElementById('zapret-profile-badge');
  if (badge) {
    const current = zapretProfiles.find(p => p.id === selectedZapretProfile);
    badge.textContent = current ? current.label : 'Выключен';
  }

  // Description
  const descEl = document.getElementById('zapret-profile-desc');
  if (descEl) {
    const current = zapretProfiles.find(p => p.id === selectedZapretProfile);
    descEl.textContent = current ? current.description : 'Zapret цепочки не активны. Используется только пресет оператора.';
  }

  // Chain details
  renderZapretChainDetails();
}

function renderZapretChainDetails() {
  const container = document.getElementById('zapret-chains-detail');
  const listEl = document.getElementById('zapret-chains-list');
  if (!container || !listEl) return;

  const current = zapretProfiles.find(p => p.id === selectedZapretProfile);
  if (!current || !current.chain_details || current.chain_details.length === 0) {
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');

  listEl.innerHTML = current.chain_details.map(ch => {
    const protoBadge = ch.proto === 'tcp'
      ? '<span style="background:#20808D;color:#fff;padding:1px 6px;border-radius:4px;font-size:0.65rem;font-weight:600">TCP</span>'
      : '<span style="background:#A84B2F;color:#fff;padding:1px 6px;border-radius:4px;font-size:0.65rem;font-weight:600">UDP</span>';

    // Desync mode badge — highlight multi-phase combos
    const desyncModes = (ch.desync || '').split(',');
    const desyncBadge = ch.desync
      ? `<span style="background:var(--surface-secondary,#1e1e2e);padding:1px 6px;border-radius:4px;font-size:0.65rem${
          desyncModes.length >= 3 ? ';border:1px solid var(--primary,#20808D)' : ''
        }">${escapeHtml(ch.desync)}</span>`
      : '';

    const ports = ch.ports || '';
    const repeats = ch.repeats ? `\u00d7${ch.repeats}` : '';

    // Build detailed extras — v72.x features
    let extras = [];
    if (ch.seqovl)               extras.push(`seqovl=${ch.seqovl}`);
    if (ch.fooling)              extras.push(`fool=${ch.fooling}`);
    if (ch.fake_type)            extras.push(`fake-${ch.fake_type}`);
    if (ch.fake_tls_mod)         extras.push(`tls-mod=${ch.fake_tls_mod}`);
    if (ch.split_pos)            extras.push(`pos=${ch.split_pos}`);
    if (ch.ip_id)                extras.push(`ipid=${ch.ip_id}`);
    if (ch.ttl)                  extras.push(`ttl=${ch.ttl}`);
    if (ch.autottl)              extras.push(`autottl=${ch.autottl}`);
    if (ch.fakedsplit_altorder)  extras.push('altorder');
    if (ch.hostfakesplit_midhost) extras.push(`midhost=${ch.hostfakesplit_midhost}`);
    if (ch.hostlist)             extras.push(ch.hostlist);
    if (ch.ipset)                extras.push(ch.ipset);
    if (ch.host)                 extras.push(ch.host);
    if (ch.filter_l7)            extras.push(`L7=${ch.filter_l7}`);
    if (ch.cutoff)               extras.push(`cutoff=${ch.cutoff}`);
    if (ch.any_protocol)         extras.push('any-proto');

    return `
      <div style="display:flex;align-items:center;gap:var(--sp-2);padding:var(--sp-2) var(--sp-3);background:var(--surface-secondary,rgba(255,255,255,.03));border-radius:var(--r-md);font-size:var(--text-sm);flex-wrap:wrap">
        ${protoBadge}
        <span style="font-weight:600;min-width:130px">${escapeHtml(ch.name)}</span>
        <span style="opacity:.7">:${escapeHtml(ports)}</span>
        ${desyncBadge}
        <span style="color:var(--primary,#20808D);font-weight:500">${repeats}</span>
        <span style="opacity:.5;font-size:0.6rem;margin-left:auto;text-align:right;max-width:50%">${escapeHtml(extras.join(' \u00b7 '))}</span>
      </div>
    `;
  }).join('');
}

async function selectZapretProfile(profileId) {
  try {
    const data = await apiFetch('/api/dpi/zapret/profile', {
      method: 'POST',
      body: JSON.stringify({ profile: profileId }),
    });
    if (data.ok) {
      selectedZapretProfile = profileId;
      appState.config.zapret_profile = profileId;
      renderZapretProfiles();

      const current = zapretProfiles.find(p => p.id === profileId);
      const label = current ? current.label : 'Выключен';
      showToast(`Zapret: ${label}`, 'success');
    }
  } catch (_) {}
}

// ─── Network Interfaces ───────────────────────────────────────────────────────


async function loadNetworkInterfaces() {
  try {
    const ifaces = await apiFetch('/api/network/interfaces');
    renderInterfaceTable(ifaces);
    populateInterfaceSelect(ifaces);
  } catch (_) {}
}

function renderInterfaceTable(ifaces) {
  const tbody = document.getElementById('iface-tbody');
  if (!tbody) return;
  tbody.innerHTML = ifaces.map(i => `
    <tr>
      <td>${escapeHtml(i.name)}</td>
      <td>${i.ips.join(', ') || '—'}</td>
      <td><span class="badge ${i.up ? 'badge--active' : 'badge--inactive'}">${i.up ? 'Активен' : 'Выкл'}</span></td>
      <td><button class="btn btn--sm" onclick="selectInterface('${escapeHtml(i.name)}')">Выбрать</button></td>
    </tr>
  `).join('');
}

function populateInterfaceSelect(ifaces) {
  const sel = document.getElementById('sel-interface');
  if (!sel) return;
  const current = appState.config.interface || 'auto';
  sel.innerHTML = `<option value="auto">Авто</option>` +
    ifaces.map(i => `<option value="${escapeHtml(i.name)}" ${i.name === current ? 'selected' : ''}>${escapeHtml(i.name)}</option>`).join('');
}

function selectInterface(name) {
  saveConfig({ interface: name });
}

// ─── E2E Sessions ─────────────────────────────────────────────────────────

async function loadE2ESessions() {
  try {
    const sessions = await apiFetch('/api/e2e/sessions');
    renderE2ESessions(sessions);
  } catch (_) {}
}

function renderE2ESessions(sessions) {
  const list = document.getElementById('e2e-list');
  if (!list) return;
  if (!sessions.length) {
    list.innerHTML = '<div class="text-muted text-sm" style="padding:var(--sp-4)">Нет активных сессий</div>';
    return;
  }
  list.innerHTML = sessions.map(s => `
    <div class="item-row">
      <div class="item-row__icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <div class="item-row__body">
        <div class="item-row__title">${s.id} — ${s.peer}</div>
        <div class="item-row__sub">${s.cipher}${s.pq_enabled ? ' + Kyber1024' : ''} · ${s.msg_count} сообщений</div>
      </div>
      <span class="badge badge--${s.status === 'active' ? 'active' : 'warn'}">${s.status}</span>
      <button class="btn btn--sm btn--danger" onclick="deleteE2ESession('${s.id}')">✕</button>
    </div>
  `).join('');
}

async function createE2ESession() {
  try {
    const data = await apiFetch('/api/e2e/sessions', { method: 'POST' });
    showToast('E2E сессия создана: ' + data.session.id, 'success');
    loadE2ESessions();
  } catch (_) {}
}

async function deleteE2ESession(id) {
  try {
    await apiFetch('/api/e2e/sessions/' + id, { method: 'DELETE' });
    loadE2ESessions();
  } catch (_) {}
}

// ─── I2P Tunnels ──────────────────────────────────────────────────────────

async function loadI2PTunnels() {
  try {
    const tunnels = await apiFetch('/api/i2p/tunnels');
    renderI2PTunnels(tunnels);
  } catch (_) {}
}

function renderI2PTunnels(tunnels) {
  const list = document.getElementById('i2p-list');
  if (!list) return;
  if (!tunnels.length) {
    list.innerHTML = '<div class="text-muted text-sm" style="padding:var(--sp-4)">Нет активных туннелей</div>';
    return;
  }
  list.innerHTML = tunnels.map(t => `
    <div class="item-row">
      <div class="item-row__icon" style="background:var(--purple-dim);color:var(--purple);">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
      </div>
      <div class="item-row__body">
        <div class="item-row__title">${t.id} (${t.type})</div>
        <div class="item-row__sub">${t.hops} хопов · ${t.destination}</div>
      </div>
      <span class="badge badge--${t.status === 'ready' ? 'active' : 'warn'}">${t.status}</span>
      <button class="btn btn--sm btn--danger" onclick="deleteI2PTunnel('${t.id}')">✕</button>
    </div>
  `).join('');
}

async function createI2PTunnel() {
  try {
    const data = await apiFetch('/api/i2p/tunnels', { method: 'POST' });
    showToast('Туннель создан: ' + data.tunnel.id, 'success');
    loadI2PTunnels();
  } catch (_) {}
}

async function deleteI2PTunnel(id) {
  try {
    await apiFetch('/api/i2p/tunnels/' + id, { method: 'DELETE' });
    loadI2PTunnels();
  } catch (_) {}
}

// ─── License ──────────────────────────────────────────────────────────────

// Глобальное состояние лицензии
let currentLicense = { status: 'inactive', modules: [], plan: '' };

// Маппинг всех модулей NCP
const MODULE_NAMES = {
  dpi_bypass: 'DPI обход', traffic_stats: 'Статистика трафика',
  geneva_basic: 'Geneva GA (базовый)', geneva_full: 'Geneva GA (полный)',
  dns_leak: 'DNS Leak Prevention', session_frag: 'Session Fragmenter',
  cross_layer: 'Cross-Layer Correlator', rtt_equalizer: 'RTT Equalizer',
  volume_norm: 'Volume Normalizer', behavioral_cloak: 'Behavioral Cloak',
  time_breaker: 'Time Correlation Breaker', covert_channel: 'Covert Channel',
  wf_defense: 'WF Defense', self_test: 'Self-Test Monitor',
  protocol_rotation: 'Protocol Rotation', as_router: 'AS-Aware Router',
  geo_obfuscator: 'Geo Obfuscator', e2e_encryption: 'E2E шифрование',
  i2p: 'I2P интеграция', mimicry: 'Мимикрия трафика',
  postquantum: 'Постквантовое шифрование'
};

async function loadLicense() {
  try {
    const lic = await apiFetch('/api/license');
    currentLicense = lic;
    renderLicense(lic);
  } catch (_) {}
}

function renderLicense(lic) {
  const statusMap = { inactive: 'НЕ АКТИВНА', active: 'АКТИВНА', expired: 'ИСТЕКЛА' };
  setEl('lic-status-text', statusMap[lic.status] || lic.status.toUpperCase());
  const el = document.getElementById('lic-status-text');
  if (el) el.className = 'license-status-text ' + lic.status;

  // План
  setEl('lic-plan', lic.plan_label || lic.plan || '—');

  // Дни
  if (lic.status === 'active') {
    if (lic.days_remaining >= 99999) {
      setEl('lic-days', 'Пожизненная');
    } else {
      setEl('lic-days', lic.days_remaining + ' дней осталось');
    }
  } else {
    setEl('lic-days', '—');
  }

  // Истечение
  if (lic.expires === 'lifetime') {
    setEl('lic-expires', 'Бессрочно');
  } else {
    setEl('lic-expires', lic.expires || '—');
  }

  // Ключ
  setEl('lic-key-display', lic.key || '—');

  // Список модулей
  const flist = document.getElementById('lic-features');
  if (flist) {
    const allModules = Object.keys(MODULE_NAMES);
    const activeModules = lic.modules || lic.features || [];
    flist.innerHTML = allModules.map(m => {
      const active = activeModules.includes(m);
      return `<div class="toggle-wrap" style="padding:var(--sp-2) 0">
        <span class="toggle-name">${MODULE_NAMES[m]}</span>
        <span class="badge ${active ? 'badge--active' : 'badge--locked'}">${active ? '✓ Доступно' : '🔒 Заблокирован'}</span>
      </div>`;
    }).join('');
  }

  // Показываем/скрываем кнопку деактивации
  const deactBtn = document.getElementById('btn-deactivate-license');
  if (deactBtn) deactBtn.classList.toggle('hidden', lic.status !== 'active');

  // Скрываем поле ввода ключа если активна
  const keyInput = document.getElementById('license-activate-form');
  if (keyInput) keyInput.classList.toggle('hidden', lic.status === 'active');
}

async function activateLicense() {
  const keyEl = document.getElementById('inp-license-key');
  const key = keyEl?.value?.trim();
  if (!key) { showToast('Введите ключ лицензии', 'warn'); return; }
  try {
    const data = await apiFetch('/api/license/activate', {
      method: 'POST', body: JSON.stringify({ key })
    });
    if (data.ok) {
      currentLicense = data.license;
      renderLicense(data.license);
      showToast('Лицензия активирована: ' + (data.license.plan_label || data.license.plan), 'success');
    } else {
      showToast(data.error || 'Ошибка активации', 'error');
    }
  } catch (e) {
    showToast('Ошибка сервера', 'error');
  }
}

async function deactivateLicense() {
  if (!confirm('Деактивировать лицензию?')) return;
  try {
    await apiFetch('/api/license/deactivate', { method: 'POST' });
    currentLicense = { status: 'inactive', modules: [], plan: '' };
    renderLicense(currentLicense);
    showToast('Лицензия деактивирована', 'info');
  } catch (_) {}
}

// ─── Geneva ───────────────────────────────────────────────────────────────

async function refreshGenevaStatus() {
  try {
    const g = await apiFetch('/api/geneva/status');
    setEl('gen-generation', g.generation);
    setEl('gen-fitness', (g.best_fitness * 100).toFixed(1) + '%');
    setEl('gen-status', g.running ? 'Эволюция...' : 'Остановлена');
    document.getElementById('btn-gen-start')?.classList.toggle('hidden', g.running);
    document.getElementById('btn-gen-stop')?.classList.toggle('hidden', !g.running);
    updateGenevaChart(g.fitness_history || []);
  } catch (_) {}
}

async function startGeneva() {
  try {
    await apiFetch('/api/geneva/start', { method: 'POST' });
    showToast('Geneva GA запущена', 'success');
    refreshGenevaStatus();
  } catch (_) {}
}

async function stopGeneva() {
  try {
    const data = await apiFetch('/api/geneva/stop', { method: 'POST' });
    showToast(`Geneva остановлена. Поколение: ${data.geneva?.generation}`, 'warn');
    refreshGenevaStatus();
  } catch (_) {}
}

// ─── Rotate Identity ─────────────────────────────────────────────────────

async function rotateIdentity() {
  const btn = document.getElementById('btn-rotate');
  if (btn) { btn.disabled = true; btn.textContent = 'Ротация...'; }
  try {
    await apiFetch('/api/rotate', { method: 'POST' });
    showToast('Идентичность ротирована', 'success');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Ротировать'; }
  }
}

// ─── Settings ────────────────────────────────────────────────────────────

function loadSettings() {
  applyConfigToUI();
}

function exportConfig() {
  const blob = new Blob([JSON.stringify(appState.config, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'ncp-config.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function importConfig() {
  const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.json';
  inp.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const text = await file.text();
    try {
      const cfg = JSON.parse(text);
      await saveConfig(cfg);
      applyConfigToUI();
    } catch (err) { showToast('Ошибка парсинга файла', 'error'); }
  };
  inp.click();
}

// ─── Self-Test ────────────────────────────────────────────────────────────

async function runSelfTest() {
  try {
    const data = await apiFetch('/api/selftest/run', { method: 'POST' });
    const r = data.result || data;
    showToast(
      `Тест завершён: ${r.score}/100, проблем: ${r.issues}`,
      r.score >= 90 ? 'success' : r.score >= 70 ? 'warn' : 'error'
    );
    loadModuleStats();
  } catch (_) {}
}

function renderSelfTestHistory(history) {
  const el = document.getElementById('self-test-history');
  if (!el) return;
  if (!history || !history.length) {
    el.innerHTML = '<tr><td colspan="3" class="text-muted" style="text-align:center;padding:var(--sp-3)">Нет данных</td></tr>';
    return;
  }
  el.innerHTML = history.slice(-5).reverse().map(h =>
    `<tr>
      <td class="text-muted" style="font-size:var(--text-xs)">${escapeHtml(h.ts || h.time || '—')}</td>
      <td><span class="badge badge--${h.score >= 90 ? 'active' : h.score >= 70 ? 'warn' : 'inactive'}">${h.score}/100</span></td>
      <td class="text-muted" style="font-size:var(--text-xs)">${h.issues} проблем</td>
    </tr>`
  ).join('');
}

// ─── Log Controls ─────────────────────────────────────────────────────────

function setLogFilter(level) {
  appState.logFilter = level;
  document.querySelectorAll('[data-log-level]').forEach(b => {
    b.classList.toggle('btn--primary', b.dataset.logLevel === level);
  });
  reRenderLogs();
}

function reRenderLogs() {
  const viewer = document.getElementById('log-viewer');
  if (!viewer) return;
  viewer.innerHTML = '';
  appState.logBuffer.forEach(appendLogEntry);
}

function clearLogs() {
  appState.logBuffer = [];
  const viewer = document.getElementById('log-viewer');
  if (viewer) viewer.innerHTML = '';
}

function copyLogs() {
  const text = appState.logBuffer.map(l => `[${l.ts}] ${l.level} ${l.msg}`).join('\n');
  navigator.clipboard.writeText(text).then(() => showToast('Логи скопированы', 'success'));
}

// ─── DOM Helpers ─────────────────────────────────────────────────────────

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '—';
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  if (el.type === 'checkbox') el.checked = !!val;
  else el.value = val ?? '';
}

function setToggle(id, val) {
  const inp = document.getElementById(id);
  if (inp) inp.checked = !!val;
}

function setSlider(id, val, displayId) {
  const el = document.getElementById(id);
  if (el) el.value = val ?? 0;
  if (displayId) setEl(displayId, val ?? 0);
}

function escapeHtml(str) {
  // R7-WEB-06: Also escape single quotes to prevent DOM XSS in onclick handlers
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function formatNumber(n) {
  if (!n && n !== 0) return '—';
  return Number(n).toLocaleString('ru-RU');
}

// ─── Hamburger / Sidebar ─────────────────────────────────────────────────

document.getElementById('hamburger')?.addEventListener('click', () => {
  document.querySelector('.sidebar')?.classList.toggle('open');
});

// ─── Sidebar Navigation ───────────────────────────────────────────────────

document.querySelectorAll('[data-nav]').forEach(el => {
  el.addEventListener('click', () => navigateTo(el.dataset.nav));
});

// ─── Toggle Change Handlers ───────────────────────────────────────────────

function bindToggleSave(id, key) {
  document.getElementById(id)?.addEventListener('change', (e) => saveConfig({ [key]: e.target.checked }));
}

function bindSelectSave(id, key) {
  document.getElementById(id)?.addEventListener('change', (e) => saveConfig({ [key]: e.target.value }));
}

function bindInputSave(id, key, transform) {
  document.getElementById(id)?.addEventListener('change', (e) => {
    const v = transform ? transform(e.target.value) : e.target.value;
    saveConfig({ [key]: v });
  });
}

function bindSlider(id, valId) {
  const el = document.getElementById(id);
  const disp = document.getElementById(valId);
  if (el && disp) {
    el.addEventListener('input', () => { disp.textContent = el.value; });
  }
}

function bindRotationProtocols() {
  document.querySelectorAll('[data-rotation-proto]')?.forEach(el => {
    el.addEventListener('change', () => {
      const checked = [];
      document.querySelectorAll('[data-rotation-proto]:checked').forEach(c => checked.push(c.dataset.rotationProto));
      saveConfig({ rotation_protocols: checked.join(',') });
    });
  });
}

function wireUpControls() {
  // ── Existing toggles ──────────────────────────────────────────────────
  bindToggleSave('toggle-tcp-frag', 'tcp_fragment');
  bindToggleSave('toggle-tls-split', 'tls_split');
  bindToggleSave('toggle-ttl-manip', 'ttl_manip');
  bindToggleSave('toggle-fake-pkt', 'fake_packets');
  bindToggleSave('toggle-pkt-disorder', 'pkt_disorder');
  bindToggleSave('toggle-sni-spoof', 'sni_spoof');
  bindToggleSave('toggle-ech', 'ech_enabled');
  bindToggleSave('toggle-paranoid', 'paranoid_mode');
  bindToggleSave('toggle-auto-rotate', 'auto_rotate');
  bindToggleSave('toggle-antiforensics', 'antiforensics');
  bindToggleSave('toggle-autostart', 'autostart');
  bindToggleSave('toggle-burst-morph', 'burst_morphing');
  bindToggleSave('toggle-postquantum', 'postquantum');
  bindToggleSave('toggle-i2p', 'i2p_enabled');
  bindToggleSave('toggle-garlic', 'garlic_routing');
  bindToggleSave('toggle-port-knock', 'port_knocking');

  // ── New module toggles ────────────────────────────────────────────────
  bindToggleSave('toggle-pipeline-enabled',          'pipeline_enabled');
  bindToggleSave('toggle-dns-leak-prevention',       'dns_leak_prevention');
  bindToggleSave('toggle-session-fragmenter',        'session_fragmenter');
  bindToggleSave('toggle-cross-layer-enabled',       'cross_layer_enabled');
  bindToggleSave('toggle-rtt-equalizer',             'rtt_equalizer');
  bindToggleSave('toggle-volume-normalizer',         'volume_normalizer');
  bindToggleSave('toggle-behavioral-cloak',          'behavioral_cloak');
  bindToggleSave('toggle-cloak-human-sim',           'cloak_human_sim');
  bindToggleSave('toggle-time-correlation-breaker',  'time_correlation_breaker');
  bindToggleSave('toggle-covert-channel',            'covert_channel');
  bindToggleSave('toggle-wf-defense',                'wf_defense');
  bindToggleSave('toggle-self-test-enabled',         'self_test_enabled');
  bindToggleSave('toggle-protocol-rotation',         'protocol_rotation');
  bindToggleSave('toggle-as-aware-routing',          'as_aware_routing');
  bindToggleSave('toggle-as-prefer-diversity',       'as_prefer_diversity');
  bindToggleSave('toggle-geo-obfuscator',            'geo_obfuscator');

  // ── Existing selects ──────────────────────────────────────────────────
  bindSelectSave('sel-interface', 'interface');
  bindSelectSave('sel-doh', 'doh_provider');
  bindSelectSave('sel-proxy-type', 'proxy_type');
  bindSelectSave('sel-mimic', 'mimic_protocol');
  bindSelectSave('sel-tls-fp', 'tls_fingerprint');
  bindSelectSave('sel-flow', 'flow_profile');
  bindSelectSave('sel-language', 'language');

  // ── New module selects ────────────────────────────────────────────────
  bindSelectSave('sel-dns-leak-mode',          'dns_leak_mode');
  bindSelectSave('sel-session-frag-strategy',  'session_frag_strategy');
  bindSelectSave('sel-cross-layer-strictness', 'cross_layer_strictness');
  bindSelectSave('sel-volume-padding-mode',    'volume_padding_mode');
  bindSelectSave('sel-cloak-profile',          'cloak_profile');
  bindSelectSave('sel-time-break-mode',        'time_break_mode');
  bindSelectSave('sel-covert-mode',            'covert_mode');
  bindSelectSave('sel-wf-defense-mode',        'wf_defense_mode');
  bindSelectSave('sel-geo-target-country',     'geo_target_country');

  // ── Existing inputs ───────────────────────────────────────────────────
  bindInputSave('inp-proxy-host', 'proxy_host');
  bindInputSave('inp-proxy-port', 'proxy_port', Number);
  bindInputSave('inp-doh-custom', 'doh_custom');
  bindInputSave('inp-i2p-host', 'i2p_sam_host');
  bindInputSave('inp-i2p-port', 'i2p_sam_port', Number);
  bindInputSave('inp-rotate-interval', 'rotate_interval', Number);
  bindInputSave('inp-port-knock-seq', 'port_knock_seq');

  // ── New module inputs ─────────────────────────────────────────────────
  bindInputSave('inp-dns-leak-whitelist', 'dns_leak_whitelist');
  bindInputSave('inp-as-blacklist',       'as_blacklist');

  // ── Existing sliders ──────────────────────────────────────────────────
  bindSlider('range-fragment', 'val-fragment');
  bindSlider('range-jitter', 'val-jitter');
  bindSlider('range-noise', 'val-noise');
  bindSlider('range-pop', 'val-pop');
  bindSlider('range-mutation', 'val-mutation');
  bindSlider('range-hops', 'val-hops');

  document.getElementById('range-fragment')?.addEventListener('change', (e) => saveConfig({ fragment_size: Number(e.target.value) }));
  document.getElementById('range-jitter')?.addEventListener('change', (e) => saveConfig({ timing_jitter: Number(e.target.value) }));
  document.getElementById('range-noise')?.addEventListener('change', (e) => saveConfig({ noise_level: Number(e.target.value) }));
  document.getElementById('range-pop')?.addEventListener('change', (e) => saveConfig({ geneva_population: Number(e.target.value) }));
  document.getElementById('range-mutation')?.addEventListener('change', (e) => saveConfig({ geneva_mutation: Number(e.target.value) / 100 }));
  document.getElementById('range-hops')?.addEventListener('change', (e) => saveConfig({ i2p_hop_count: Number(e.target.value) }));

  // ── New module sliders ────────────────────────────────────────────────
  bindSlider('range-pipeline-workers',          'val-pipeline-workers');
  bindSlider('range-pipeline-queue-size',       'val-pipeline-queue-size');
  bindSlider('range-session-frag-min-segments', 'val-session-frag-min-segments');
  bindSlider('range-session-frag-max-segments', 'val-session-frag-max-segments');
  bindSlider('range-rtt-target-ms',             'val-rtt-target-ms');
  bindSlider('range-rtt-jitter-ms',             'val-rtt-jitter-ms');
  bindSlider('range-volume-target-kbps',        'val-volume-target-kbps');
  bindSlider('range-time-break-max-delay-ms',   'val-time-break-max-delay-ms');
  bindSlider('range-wf-defense-overhead',       'val-wf-defense-overhead');
  bindSlider('range-self-test-interval-sec',    'val-self-test-interval-sec');
  bindSlider('range-rotation-interval-min',     'val-rotation-interval-min');
  bindSlider('range-geo-relay-hops',            'val-geo-relay-hops');
  bindSlider('range-covert-bandwidth-limit-bps', 'val-covert-bandwidth-limit-bps');

  document.getElementById('range-pipeline-workers')?.addEventListener('change',          (e) => saveConfig({ pipeline_workers: Number(e.target.value) }));
  document.getElementById('range-pipeline-queue-size')?.addEventListener('change',       (e) => saveConfig({ pipeline_queue_size: Number(e.target.value) }));
  document.getElementById('range-session-frag-min-segments')?.addEventListener('change', (e) => saveConfig({ session_frag_min_segments: Number(e.target.value) }));
  document.getElementById('range-session-frag-max-segments')?.addEventListener('change', (e) => saveConfig({ session_frag_max_segments: Number(e.target.value) }));
  document.getElementById('range-rtt-target-ms')?.addEventListener('change',             (e) => saveConfig({ rtt_target_ms: Number(e.target.value) }));
  document.getElementById('range-rtt-jitter-ms')?.addEventListener('change',             (e) => saveConfig({ rtt_jitter_ms: Number(e.target.value) }));
  document.getElementById('range-volume-target-kbps')?.addEventListener('change',        (e) => saveConfig({ volume_target_kbps: Number(e.target.value) }));
  document.getElementById('range-time-break-max-delay-ms')?.addEventListener('change',   (e) => saveConfig({ time_break_max_delay_ms: Number(e.target.value) }));
  document.getElementById('range-wf-defense-overhead')?.addEventListener('change',       (e) => saveConfig({ wf_defense_overhead: Number(e.target.value) }));
  document.getElementById('range-self-test-interval-sec')?.addEventListener('change',    (e) => saveConfig({ self_test_interval_sec: Number(e.target.value) }));
  document.getElementById('range-rotation-interval-min')?.addEventListener('change',     (e) => saveConfig({ rotation_interval_min: Number(e.target.value) }));
  document.getElementById('range-geo-relay-hops')?.addEventListener('change',            (e) => saveConfig({ geo_relay_hops: Number(e.target.value) }));
  document.getElementById('range-covert-bandwidth-limit-bps')?.addEventListener('change', (e) => saveConfig({ covert_bandwidth_limit_bps: Number(e.target.value) }));

  // ── Protocol rotation checkboxes ──────────────────────────────────────
  bindRotationProtocols();

  // ── Log filter buttons ────────────────────────────────────────────────
  document.querySelectorAll('[data-log-level]').forEach(b => {
    b.addEventListener('click', () => setLogFilter(b.dataset.logLevel));
  });

  // ── Log search ────────────────────────────────────────────────────────
  document.getElementById('log-search')?.addEventListener('input', (e) => {
    appState.logSearch = e.target.value.toLowerCase();
    reRenderLogs();
  });
}

// ─── Geneva presets ───────────────────────────────────────────────────────

const genevaPresets = {
  tspu: { name: 'ТСПУ 2026', strategy: ['[TCP:flags:S]-fragment{tcp:8:false}-|'] },
  gfw: { name: 'GFW 2025', strategy: ['[TCP:flags:PA]-tamper{TCP:flags:replace:INVALID}-|'] },
  iran: { name: 'Iran DPI', strategy: ['[TCP:flags:S]-duplicate-|'] },
  universal: { name: 'Universal', strategy: ['[TCP:flags:PA]-fragment{tcp:4:false}-|'] },
};

document.querySelectorAll('[data-geneva-preset]')?.forEach(el => {
  el.addEventListener('click', () => {
    const p = genevaPresets[el.dataset.genevaPreset];
    if (p) {
      const strategyStr = p.strategy.join('\n');
      saveConfig({ geneva_strategy: strategyStr });
      const textarea = document.getElementById('inp-geneva-strategy');
      if (textarea) textarea.value = strategyStr;
      document.querySelectorAll('[data-geneva-preset]').forEach(b => b.classList.remove('active'));
      el.classList.add('active');
      showToast(`Пресет Geneva: ${p.name}`, 'success');
    }
  });
});

// ─── Initialisation ───────────────────────────────────────────────────────

async function init() {
  wireUpControls();

  // Init charts
  createTrafficChart('traffic-chart');
  createGenevaChart('geneva-chart');
  createPipelineChart('pipeline-chart');

  // Load initial data
  await loadConfig();
  await refreshStatus();

  // Start WebSocket
  const ws = new NCPWebSocket({
    onLog: onLogEntry,
    onStats: applyStats,
    onModuleStats: applyModuleStats,
    onConnect: () => { appState.wsConnected = true; },
    onDisconnect: () => { appState.wsConnected = false; },
  });
  ws.connect();

  // Poll status every 5s as fallback
  setInterval(refreshStatus, 5000);

  // Periodic stats pull when ws not connected; also poll module stats for new sections
  setInterval(async () => {
    if (!appState.wsConnected) {
      try {
        const data = await apiFetch('/api/stats');
        applyStats(data);
      } catch (_) {}
    }
    if (currentSection === 'geneva') refreshGenevaStatus();
    if (['pipeline', 'antiml', 'covert', 'transport'].includes(currentSection)) {
      loadModuleStats();
    }
  }, 2000);

  // Start on overview
  navigateTo('overview');
}

document.addEventListener('DOMContentLoaded', init);

// ─── Telegram MTProto Proxies ──────────────────────────────────────────────

async function loadTgProxies() {
  const list = document.getElementById('tg-proxy-list');
  if (!list) return;
  list.innerHTML = '<div class="text-muted text-sm">Проверяем прокси серверы...</div>';
  try {
    const proxies = await apiFetch('/api/telegram/proxies');
    if (!proxies.length) {
      list.innerHTML = '<div class="text-muted text-sm">Нет прокси в списке</div>';
      return;
    }
    list.innerHTML = proxies.map(p => {
      const statusBadge = p.alive
        ? '<span class="badge badge--active">Онлайн</span>'
        : '<span class="badge badge--inactive">Оффлайн</span>';
      const connectBtn = p.alive
        ? `<a href="${escapeHtml(p.link)}" class="btn btn--sm btn--primary" target="_blank" rel="noopener">Подключить</a>`
        : '<span class="btn btn--sm" style="opacity:0.4;pointer-events:none;">Недоступен</span>';
      return `
        <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-2);border-radius:8px;">
          <span style="font-weight:600;min-width:40px;">${escapeHtml(p.location || '??')}</span>
          <span class="text-sm" style="flex:1;font-family:var(--font-mono);">${escapeHtml(p.server)}:${p.port}</span>
          ${statusBadge}
          ${connectBtn}
        </div>`;
    }).join('');
  } catch (_) {
    list.innerHTML = '<div class="text-muted text-sm">Ошибка загрузки списка прокси</div>';
  }
}

async function checkCustomTgProxy() {
  const server = document.getElementById('tg-custom-server')?.value?.trim();
  const port   = document.getElementById('tg-custom-port')?.value?.trim() || '443';
  const secret = document.getElementById('tg-custom-secret')?.value?.trim();
  const status = document.getElementById('tg-custom-status');

  if (!server || !secret) {
    showToast('Введите Server и Secret', 'warn');
    return;
  }

  if (status) { status.textContent = 'Проверяем...'; status.style.color = 'var(--text-muted)'; }

  try {
    const data = await apiFetch('/api/telegram/proxy/check', {
      method: 'POST',
      body: JSON.stringify({ server, port: Number(port), secret }),
    });
    if (data.alive) {
      if (status) { status.innerHTML = '✓ Прокси доступен'; status.style.color = 'var(--green)'; }
      // Open tg:// deep link
      window.open(data.link, '_blank');
      showToast('Прокси доступен — Telegram откроется для подключения', 'success');
    } else {
      if (status) { status.innerHTML = '✗ Прокси не отвечает'; status.style.color = 'var(--red)'; }
      showToast('Прокси не отвечает — попробуйте другой', 'warn');
    }
  } catch (_) {
    if (status) { status.textContent = 'Ошибка проверки'; status.style.color = 'var(--red)'; }
  }
}
