# Attack Framework — Полный список реализованных модулей

## Статистика

- **Всего модулей:** 23 (7 базовых атак + 4 advanced + 12 security detection)
- **API endpoints:** 56
- **Строки кода:** ~7,000+

---

## Базовые атаки (7 модулей)

### 1. ECS (EDNS Client Subnet) Attack
**Файл:** `src/attacks/implementations.py`
**API:** Через AttackManager

Инъекция поддельного subnet в DNS запросы для обхода гео-блокировки и DPI.

### 2. Fragmentation Attack
**Файл:** `src/attacks/implementations.py`

Фрагментация пакетов для обхода DPI систем, которые не могут корректно собирать фрагменты.

### 3. TTL Manipulation
**Файл:** `src/attacks/implementations.py`

Манипуляция TTL для cache poisoning атак и обхода DPI.

### 4. HTTP Obfuscation
**Файл:** `src/attacks/implementations.py`

Обфускация HTTP headers и payload (4 подтипа: case variation, whitespace, encoding, header splitting).

### 5. TLS Split Attack
**Файл:** `src/attacks/implementations.py`

Разделение TLS handshake по TCP сегментам для обхода DPI.

### 6. Protocol Rotation
**Файл:** `src/attacks/implementations.py`

Ротация через HTTP/1.1, H2, QUIC, WebSocket для обхода protocol-specific DPI.

### 7. Adversarial Padding
**Файл:** `src/attacks/implementations.py`

Добавление adversarial bytes для обхода ML-классификаторов (ET-BERT).

---

## Advanced модули (4 модуля)

### 8. WebRTC Leak Prevention
**Файл:** `src/attacks/webrtc_leak.py`
**API:** `POST/GET /api/detect/webrtc/{target}`

Обнаружение IP/DNS leaks через STUN requests, ICE candidates, DNS queries.

### 9. Browser Fingerprint Masking
**Файл:** `src/attacks/browser_fingerprint.py`
**API:** `POST/GET /api/detect/fingerprint/{target}`

Детекция Canvas/WebGL/Audio fingerprinting, font enumeration.

### 10. Adversarial Training Pipeline
**Файл:** `src/training/adversarial_training.py`
**API:** `POST /api/training/retrain`

Автоматический retrain ONNX моделей на основе результатов атак.

### 11. DPI Fingerprinting
**Файл:** `src/attacks/dpi_fingerprint.py`
**API:** `POST/GET /api/detect/dpi/{target}`

Определение типа DPI системы (Sandvine, Allot, Qosmos, Fortinet, Palo Alto, Cisco, nPuls) с auto-select bypass strategies.

---

## Security Detection модули (12 модулей)

### 12. DNS over HTTPS/TLS Leak Detection
**Файл:** `src/attacks/dns_leak.py`
**API:** `POST/GET /api/detect/dns-leak/{target}`

Обнаружение утечек в DoH/DoT через SNI, HTTP headers, timing correlations.

### 13. ESNI/ECH Testing
**Файл:** `src/attacks/esni_ech.py`
**API:** `POST/GET /api/detect/esni-ech/{target}`

Тестирование поддержки ESNI/ECH, обнаружение fallback и блокировки.

### 14. WebSocket Tunnel Detection
**Файл:** `src/attacks/websocket_tunnel.py`
**API:** `POST/GET /api/detect/websocket-tunnel/{target}`

Обнаружение WebSocket-based tunneling (wstunnel, websockify) через frame analysis, timing correlation.

### 15. Timing Side-Channel Detection
**Файл:** `src/attacks/timing_sidechannel.py`
**API:** `POST/GET /api/detect/timing/{target}`

Обнаружение timing-based traffic analysis через inter-packet timing, request-response correlation, TCP timestamps, jitter analysis.

### 16. Certificate Transparency Monitoring
**Файл:** `src/attacks/cert_transparency.py`
**API:** `POST/GET /api/detect/ct/{target}`

Мониторинг CT logs для обнаружения блокировки доменов, subdomain enumeration, change detection.

### 17. Traffic Pattern Analysis & Correlation
**Файл:** `src/attacks/traffic_pattern.py`
**API:** `POST/GET /api/detect/traffic-pattern/{target}`

Анализ traffic patterns для ML-based DPI через packet size distribution, flow patterns, bidirectional correlation, burst patterns, entropy analysis.

### 18. HTTP/2 PUSH Abuse Testing
**Файл:** `src/attacks/http2_push.py`
**API:** `POST/GET /api/detect/http2-push/{target}`

Тестирование HTTP/2 server push для DPI bypass через unauthorized push, cross-origin push, timing manipulation.

### 19. Multi-Path TCP (MPTCP) Testing
**Файл:** `src/attacks/mptcp_test.py`
**API:** `POST/GET /api/detect/mptcp/{target}`

Тестирование MPTCP для DPI bypass через subflow detection, path diversity, handover analysis.

### 20. IPv6 Transition Mechanisms
**Файл:** `src/attacks/ipv6_transition.py`
**API:** `POST/GET /api/detect/ipv6/{target}`

Тестирование IPv6 transition механизмов (6to4, Teredo, NAT64, ISATAP) для обхода IPv4-only DPI.

### 21. Proxy Chain Validation
**Файл:** `src/attacks/proxy_chain.py`
**API:** `POST/GET /api/detect/proxy-chain/{target}`

Валидация proxy chains на предмет leaks (IP, DNS, WebRTC) и performance analysis.

### 22. Browser Extension Fingerprint
**Файл:** `src/attacks/browser_extension.py`
**API:** `POST/GET /api/detect/extension/{target}`

Обнаружение browser extension fingerprinting через resource detection, API detection, behavior analysis, timing patterns, DOM modifications.

### 23. Protocol Downgrade Attack
**Файл:** `src/attacks/protocol_downgrade.py`
**API:** `POST/GET /api/detect/downgrade/{target}`

Тестирование protocol downgrade vulnerabilities (TLS downgrade, HTTP downgrade, QUIC downgrade, weak ciphers, weak algorithms).

---

## API Endpoints (56 total)

### Campaigns (9 endpoints)
- `GET /api/health`
- `GET /api/attacks`
- `POST /api/campaigns/start`
- `POST /api/campaigns/{id}/stop`
- `GET /api/campaigns`
- `GET /api/campaigns/{id}`
- `GET /api/campaigns/{id}/summary`
- `GET /api/campaigns/{id}/report/json`
- `GET /api/campaigns/{id}/report/html`

### WebSocket (1 endpoint)
- `WS /ws/{campaign_id}`

### Poller Engine (10 endpoints)
- `GET /api/poller/targets`
- `POST /api/poller/targets`
- `GET /api/poller/targets/{name}`
- `DELETE /api/poller/targets/{name}`
- `POST /api/poller/targets/{name}/run`
- `GET /api/poller/targets/{name}/history`
- `GET /api/poller/targets/{name}/trend`
- `POST /api/poller/start`
- `POST /api/poller/stop`
- `GET /api/poller/status`

### Prometheus (1 endpoint)
- `GET /metrics`

### Advanced Detection (7 endpoints)
- `POST/GET /api/detect/webrtc/{target}`
- `POST/GET /api/detect/fingerprint/{target}`
- `POST/GET /api/detect/dpi/{target}`
- `POST /api/training/retrain`

### Security Detection (24 endpoints)
- `POST/GET /api/detect/dns-leak/{target}`
- `POST/GET /api/detect/esni-ech/{target}`
- `POST/GET /api/detect/websocket-tunnel/{target}`
- `POST/GET /api/detect/timing/{target}`
- `POST/GET /api/detect/ct/{target}`
- `POST/GET /api/detect/traffic-pattern/{target}`
- `POST/GET /api/detect/http2-push/{target}`
- `POST/GET /api/detect/mptcp/{target}`
- `POST/GET /api/detect/ipv6/{target}`
- `POST/GET /api/detect/proxy-chain/{target}`
- `POST/GET /api/detect/extension/{target}`
- `POST/GET /api/detect/downgrade/{target}`

---

## Интеграция

### PollerEngine
**Файл:** `src/core/poller_engine.py`

Автоматическое тестирование по расписанию с SQLite storage, trend analysis, alerts.

### Prometheus Export
**Файл:** `src/core/prometheus_export.py`

Экспорт метрик в Prometheus format для Grafana.

### Report Generator
**Файл:** `src/reports/report_generator.py`

Генерация JSON и HTML отчётов с графиками и рекомендациями.

---

## Зависимости

```txt
# Basic
fastapi>=0.100.0
uvicorn>=0.23.0
pydantic>=2.0.0
websockets>=11.0
aiohttp>=3.8.0

# ML/Training
numpy>=1.24.0
onnx>=1.14.0
onnxruntime>=1.15.0
```

---

## Структура файлов

```
attack-framework/
├── src/
│   ├── attacks/
│   │   ├── implementations.py        # 7 базовых атак
│   │   ├── webrtc_leak.py            # WebRTC leak detection
│   │   ├── browser_fingerprint.py    # Browser fingerprinting detection
│   │   ├── dpi_fingerprint.py        # DPI system fingerprinting
│   │   ├── dns_leak.py               # DNS over HTTPS/TLS leak detection
│   │   ├── esni_ech.py               # ESNI/ECH testing
│   │   ├── websocket_tunnel.py       # WebSocket tunnel detection
│   │   ├── timing_sidechannel.py     # Timing side-channel detection
│   │   ├── cert_transparency.py      # Certificate transparency monitoring
│   │   ├── traffic_pattern.py        # Traffic pattern analysis
│   │   ├── http2_push.py             # HTTP/2 push abuse testing
│   │   ├── mptcp_test.py             # MPTCP testing
│   │   ├── ipv6_transition.py        # IPv6 transition testing
│   │   ├── proxy_chain.py            # Proxy chain validation
│   │   ├── browser_extension.py      # Browser extension fingerprinting
│   │   └── protocol_downgrade.py     # Protocol downgrade testing
│   ├── training/
│   │   └── adversarial_training.py   # Auto-retrain ONNX models
│   ├── core/
│   │   ├── base_attack.py            # Base attack class
│   │   ├── attack_manager.py         # Campaign orchestration
│   │   ├── poller_engine.py          # Scheduled testing
│   │   └── prometheus_export.py      # Prometheus metrics
│   ├── api/
│   │   ├── server.py                 # FastAPI server
│   │   ├── poller_routes.py          # Poller & Prometheus API
│   │   ├── advanced_routes.py        # Advanced modules API
│   │   └── security_routes.py        # Security detection API
│   └── reports/
│       └── report_generator.py       # JSON + HTML reports
├── reports/                          # Generated reports
├── data/                             # SQLite database
├── run_server.py                     # Entry point
└── requirements.txt
```

---

## Лицензия

AGPL-3.0-only
