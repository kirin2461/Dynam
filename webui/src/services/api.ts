import type {
  TrafficData,
  AppConfig,
  LogEntry,
  AdversaryTestParams,
  AdversaryTestResults,
  AppStats,
} from '@/types';

const API_BASE = '/api';

// ─── Per-start API token ────────────────────────────────────────────
// The backend injects <meta name="ncp-token" content="…"> into the index
// page; every /api request must carry it as X-NCP-Token.
let tokenCache: string | null = null;
let tokenPromise: Promise<string | null> | null = null;

export function getToken(): Promise<string | null> {
  if (tokenCache) return Promise.resolve(tokenCache);
  if (!tokenPromise) {
    tokenPromise = fetch('/api/token', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (j && typeof j.token === 'string' && j.token) {
          tokenCache = j.token;
          return tokenCache;
        }
        // Fallback: meta tag injected into the served index page
        return fetch('/', { cache: 'no-store' })
          .then((r) => r.text())
          .then((html) => {
            const m = html.match(/name="ncp-token"\s+content="([^"]+)"/);
            tokenCache = m ? m[1] : null;
            return tokenCache;
          });
      })
      .catch(() => null);
  }
  return tokenPromise;
}

async function fetchJson<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = await getToken();
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-NCP-Token': token } : {}),
      ...(options.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

// ─── Adapters: real backend → UI types ──────────────────────────────

const LEVEL_MAP: Record<string, number> = {
  DEBUG: 0, INFO: 1, WARN: 2, WARNING: 2, ERROR: 3, CRITICAL: 4, FATAL: 4,
};

function adaptLog(e: Record<string, unknown>): LogEntry {
  const rawLevel = e.level;
  let level = 1;
  if (typeof rawLevel === 'number') level = rawLevel;
  else if (typeof rawLevel === 'string') level = LEVEL_MAP[rawLevel.toUpperCase()] ?? 1;
  return {
    timestamp: String(e.timestamp || e.ts || ''),
    level,
    source: String(e.source || 'server'),
    message: String(e.message || e.msg || ''),
  };
}

function adaptStats(s: Record<string, any>): AppStats {
  const num = (v: unknown, d = 0) => (typeof v === 'number' ? v : d);
  return {
    total_bytes: num(s.bytes_recv) + num(s.bytes_sent),
    total_packets: num(s.packets_processed),
    total_connections: num(s.active_connections),
    avg_bandwidth: num(s.speed_up) + num(s.speed_down),
    avg_stealth: num(s.avg_stealth),
    min_stealth: num(s.min_stealth),
    max_stealth: num(s.max_stealth),
    median_stealth: num(s.median_stealth, num(s.avg_stealth)),
    onnx_inferences: num(s.onnx_inferences),
    onnx_detections: num(s.onnx_detections),
    onnx_detection_rate: num(s.onnx_detection_rate),
    onnx_avg_confidence: num(s.onnx_avg_confidence),
    total_attacks: num(s.total_attacks),
    successful_attacks: num(s.successful_attacks),
    attack_success_rate: num(s.attack_success_rate),
  };
}

function adaptTraffic(t: Record<string, any>): TrafficData {
  const conns = Array.isArray(t.connections) ? t.connections : [];
  return {
    total_bytes: typeof t.total_bytes === 'number' ? t.total_bytes : 0,
    total_packets: typeof t.total_packets === 'number' ? t.total_packets : 0,
    connections: conns.map((c: Record<string, any>) => ({
      source: String(c.source || c.laddr || ''),
      destination: String(c.destination || c.raddr || ''),
      protocol: String(c.protocol || c.proto || 'tcp'),
      bytes: Number(c.bytes || 0),
      packets: Number(c.packets || 0),
      stealth_score: Number(c.stealth_score || 0),
      onnx_detected: Boolean(c.onnx_detected),
      onnx_probability: Number(c.onnx_probability || 0),
      status: String(c.status || ''),
    })),
  };
}

function adaptConfig(c: Record<string, any>): AppConfig {
  const num = (v: unknown, d = 0) => (typeof v === 'number' ? v : d);
  return {
    onnx_model_path: String(c.onnx_model_path || ''),
    onnx_threshold: num(c.onnx_threshold, 0.5),
    onnx_weight: num(c.onnx_weight, 0.3),
    onnx_enabled: Boolean(c.onnx_enabled),
    dpi_strategy: String(c.dpi_strategy || c.strategy || 'balanced'),
    auto_rotate: Boolean(c.auto_rotate),
    proxy_host: String(c.proxy_host || ''),
    proxy_port: num(c.proxy_port, 1080),
    log_level: num(c.log_level, 1),
    log_retention_days: num(c.log_retention_days, 7),
  };
}

// ─── Public API surface (names used by the pages) ───────────────────

export const trafficApi = {
  get: () => fetchJson<Record<string, unknown>>('/traffic').then(adaptTraffic),
};

export const configApi = {
  get: () => fetchJson<Record<string, unknown>>('/config').then(adaptConfig),
  // Backend accepts POST /api/config with a flat dict.
  update: (config: AppConfig) =>
    fetchJson<Record<string, unknown>>('/config', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
};

export const logsApi = {
  get: async (limit = 1000): Promise<{ logs: LogEntry[] }> => {
    const raw = await fetchJson<unknown>(`/logs?n=${limit}`);
    const arr = Array.isArray(raw) ? raw : ((raw as any)?.logs ?? []);
    return { logs: (arr as Record<string, unknown>[]).map(adaptLog) };
  },
  clear: () =>
    fetchJson<{ success: boolean }>('/logs', { method: 'DELETE' }).then(
      (r) => Boolean(r?.success),
    ),
};

export const adversaryApi = {
  run: (params: AdversaryTestParams & { target?: string }) =>
    fetchJson<Record<string, unknown>>('/adversary/run', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  getStatus: async (): Promise<{
    progress: number;
    status: string;
    results?: AdversaryTestResults;
  }> => {
    const r = await fetchJson<Record<string, unknown>>('/adversary/status');
    return {
      progress: Number(r.progress || 0),
      status: String(r.status || 'idle'),
      results: (r.results as AdversaryTestResults) || undefined,
    };
  },
};

export const statsApi = {
  get: () => fetchJson<Record<string, unknown>>('/stats').then(adaptStats),
};

export const healthApi = {
  check: () => fetchJson<{ status: string }>('/health'),
};

// ─── Additional endpoints used by the reworked pages ────────────────

export const stealthApi = {
  benchmark: (params: { strategy?: string; samples?: number; runs?: number }) =>
    fetchJson<Record<string, any>>('/stealth/benchmark', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
};

export const statusApi = {
  get: () => fetchJson<Record<string, any>>('/status'),
  start: () => fetchJson<Record<string, any>>('/start', { method: 'POST', body: '{}' }),
  stop: () => fetchJson<Record<string, any>>('/stop', { method: 'POST', body: '{}' }),
};

export const genevaApi = {
  status: () => fetchJson<Record<string, any>>('/geneva/status'),
  start: (config: Record<string, unknown> = {}) =>
    fetchJson<Record<string, any>>('/geneva/start', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  stop: () => fetchJson<Record<string, any>>('/geneva/stop', { method: 'POST', body: '{}' }),
};

export const pentestApi = {
  run: (target?: string, opts: Record<string, unknown> = {}) =>
    fetchJson<Record<string, any>>('/pentest/run', {
      method: 'POST',
      body: JSON.stringify({ ...(target ? { target } : {}), ...opts }),
    }),
  status: () => fetchJson<Record<string, any>>('/pentest/status'),
};

export const dpiApi = {
  operators: () => fetchJson<Record<string, any>>('/dpi/operators'),
  profiles: () => fetchJson<Record<string, any>>('/dpi/zapret/profiles'),
  chains: () => fetchJson<Record<string, any>>('/dpi/zapret/chains'),
};

export const modulesApi = {
  list: () => fetchJson<Record<string, any>>('/modules'),
  stats: () => fetchJson<Record<string, any>>('/modules/stats'),
  toggle: (name: string, enabled: boolean) =>
    fetchJson<Record<string, any>>('/modules/toggle', {
      method: 'POST',
      body: JSON.stringify({ name, enabled }),
    }),
};

export const selftestApi = {
  run: () => fetchJson<Record<string, any>>('/selftest/run', { method: 'POST', body: '{}' }),
};

export const monitorApi = {
  stats: () => fetchJson<Record<string, any>>('/monitor/stats'),
  events: (limit = 50) => fetchJson<Record<string, any>>(`/monitor/events?limit=${limit}`),
};

// Attack-framework detection suite (proxied by Flask at /api/detect/…)
export const detectApi = {
  run: (kind: string, target: string) =>
    fetchJson<Record<string, any>>(`/detect/${kind}`, {
      method: 'POST',
      body: JSON.stringify({ target }),
    }),
};
