# Реализованные модули Attack Framework

## 1. PollerEngine — Автоматическое тестирование

### Обоснование
Ручной запуск кампаний неудобен для production мониторинга. Нужен автоматический планировщик.

### Возможности
- **SQLite storage** — таргеты и история запусков
- **Cron-like scheduling** — настраиваемый интервал (по умолчанию 6 часов)
- **Trend analysis** — улучшение/стабильность/деградация
- **Alerts** — уведомления при падении stealth < порога
- **Manual trigger** — запуск по требованию
- **Background engine** — фоновый asyncio движок

### API Endpoints (11 штук)
```
GET    /api/poller/targets                — список таргетов
POST   /api/poller/targets                — добавить таргет
GET    /api/poller/targets/{name}         — получить таргет
DELETE /api/poller/targets/{name}         — удалить таргет
POST   /api/poller/targets/{name}/run     — запустить вручную
GET    /api/poller/targets/{name}/history — история запусков
GET    /api/poller/targets/{name}/trend   — trend analysis
POST   /api/poller/start                  — запустить движок
POST   /api/poller/stop                   — остановить движок
GET    /api/poller/status                 — статус движка
```

### Файлы
- `src/core/poller_engine.py` — PollerEngine, PollerTarget, PollerDatabase, PollerRunResult
- `src/api/poller_routes.py` — FastAPI routes для Poller

---

## 2. Prometheus Export — Метрики для мониторинга

### Обоснование
Нужна интеграция с Grafana для визуализации stealth scores, latency, trend analysis в реальном времени.

### Возможности
- **Prometheus text exposition format** — стандартный формат для Prometheus
- **Campaign метрики** — количество кампаний по статусу
- **Attack метрики** — количество атак по типу и результату
- **Stealth/Detection метрики** — scores по таргетам
- **Latency метрики** — среднее время атак по типу
- **Poller метрики** — количество таргетов, последний stealth, тренды

### Метрики
```
dynam_campaigns_total{status}              — всего кампаний по статусу
dynam_attacks_total{type,status}           — всего атак по типу и результату
dynam_stealth_score{target}                — последний stealth score
dynam_detection_rate{target}               — detection rate
dynam_attack_latency_ms{type}              — средняя latency по типу атаки
dynam_poller_targets                       — количество таргетов
dynam_poller_last_stealth{name}            — последний stealth по таргету
dynam_poller_total_runs{name}              — всего запусков по таргету
dynam_poller_trend{name}                   — тренд (1=improving, 0=stable, -1=degrading)
```

### API Endpoint
```
GET    /metrics                           — Prometheus text exposition
```

### Файлы
- `src/core/prometheus_export.py` — PrometheusExporter
- Интегрировано в `src/api/server.py`

---

## Интеграция

### Обновлённые файлы
- `src/api/server.py` — добавлены poller и prometheus экземпляры, регистрация routes
- `src/attacks/implementations.py` — исправлен импорт base_attack
- `README.md` — полная документация по новым модулям

### Статистика
- **Всего endpoints:** 25 (было 14, стало +11)
- **Новые модули:** 2 (PollerEngine, PrometheusExporter)
- **Новые файлы:** 2 (poller_engine.py, prometheus_export.py, poller_routes.py)

---

## Следующие модули (оправданы, но не реализованы)

### 3. WebRTC Leak Prevention
**Обоснование:** WebRTC может раскрывать реальный IP через STUN requests, обходя прокси/VPN.

### 4. Browser Fingerprint Masking
**Обоснование:** Canvas/WebGL/Audio fingerprinting используется для деанонимизации.

### 5. Adversarial Training Pipeline
**Обоснование:** Автоматический retrain ONNX моделей на основе результатов атак.

### 6. DPI Fingerprinting
**Обоснование:** Определение типа DPI системы для auto-select стратегий обхода.

Каждый модуль будет реализован после дополнительного обоснования.
