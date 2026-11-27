# Dynam Attack Framework

**Automated Attack Testing for Resilience Evaluation**

Полноценный фреймворк для тестирования устойчивости сайтов и сетей к атакам, включая adversarial ML-атаки, DPI evasion, и network-level атаки.

## Возможности

### 7 типов атак:
1. **ECS (EDNS Client Subnet)** — инъекция поддельного subnet в DNS
2. **Fragmentation** — фрагментация пакетов для обхода DPI
3. **TTL Manipulation** — манипуляция TTL для cache poisoning
4. **HTTP Obfuscation** — обфускация HTTP headers/payload (4 подтипа)
5. **TLS Split** — разделение TLS handshake по TCP сегментам
6. **Protocol Rotation** — ротация через HTTP/1.1, H2, QUIC, WebSocket
7. **Adversarial Padding** — adversarial bytes для обхода ML-классификаторов (ET-BERT)

### Advanced Detection Modules:
- **WebRTC Leak Prevention** — обнаружение IP/DNS leaks через STUN, ICE candidates, DNS leaks
- **Browser Fingerprint Masking** — детекция Canvas/WebGL/Audio fingerprinting, font enumeration
- **DPI Fingerprinting** — определение типа DPI системы (Sandvine, Allot, Qosmos, Fortinet, etc.) с auto-select bypass strategies
- **Adversarial Training Pipeline** — автоматический retrain ONNX моделей на основе результатов атак

### 4 режима кампании:
- **Single** — один тип атаки
- **Campaign** — последовательный запуск всех типов
- **Auto-Adaptive** — AI выбирает лучшие атаки на основе результатов
- **Stress** — высокоинтенсивное параллельное тестирование

### Poller Engine (автоматическое тестирование):
- **Планировщик** — cron-like расписание для каждого таргета (настраиваемый интервал)
- **Автозапуск** — фоновый движок автоматически тестирует все цели
- **Trend Analysis** — анализ тренда (improving/stable/degrading)
- **Alerts** — уведомления при падении stealth ниже порога
- **SQLite storage** — сохранение истории запусков
- **Manual trigger** — запуск теста по требованию

### Prometheus & Grafana:
- **`/metrics` endpoint** — Prometheus text exposition format
- Метрики кампаний, атак, stealth scores, latency
- Poller метрики: количество таргетов, последний stealth, тренды
- Интеграция с Grafana для визуализации

### Отчёты:
- **JSON** — полный машиночитаемый отчёт
- **HTML** — визуальный отчёт с графиками (Chart.js)
- Рекомендации по улучшению защиты
- Trend analysis для долгосрочного мониторинга

## Архитектура

```
attack-framework/
├── src/
│   ├── core/
│   │   ├── base_attack.py       # Абстрактный базовый класс атаки
│   │   ├── attack_manager.py    # Оркестратор кампаний
│   │   ├── poller_engine.py     # PollerEngine + SQLite storage
│   │   └── prometheus_export.py # Prometheus метрики
│   ├── attacks/
│   │   └── implementations.py   # Все 7 типов атак
│   ├── reports/
│   │   └── report_generator.py  # JSON + HTML отчёты
│   └── api/
│       ├── server.py            # FastAPI + WebSocket
│       └── poller_routes.py     # Poller & Prometheus API
├── tests/
├── reports/                     # Сгенерированные отчёты
├── data/                        # SQLite база (targets + history)
├── run_server.py                # Точка входа
└── requirements.txt
```

## Установка

```bash
cd attack-framework
pip install -r requirements.txt
```

## Запуск API сервера

```bash
python run_server.py
# или
uvicorn src.api.server:app --host 0.0.0.0 --port 8090 --reload
```

API доступен на http://localhost:8090

## API Endpoints

### REST API — Campaigns

```
GET  /api/health                          — Health check
GET  /api/attacks                         — Список доступных атак
POST /api/campaigns/start                 — Запуск кампании
POST /api/campaigns/{id}/stop             — Остановка кампании
GET  /api/campaigns                       — Список кампаний
GET  /api/campaigns/{id}                  — Прогресс кампании
GET  /api/campaigns/{id}/summary          — Итоги кампании
GET  /api/campaigns/{id}/report/json      — JSON отчёт
GET  /api/campaigns/{id}/report/html      — HTML отчёт
```

### REST API — Poller Engine

```
GET    /api/poller/targets                — Список всех таргетов
POST   /api/poller/targets                — Добавить таргет
GET    /api/poller/targets/{name}         — Получить таргет
DELETE /api/poller/targets/{name}         — Удалить таргет
POST   /api/poller/targets/{name}/run     — Запустить тест вручную
GET    /api/poller/targets/{name}/history — История запусков
GET    /api/poller/targets/{name}/trend   — Trend analysis
POST   /api/poller/start                  — Запустить движок
POST   /api/poller/stop                   — Остановить движок
GET    /api/poller/status                 — Статус движка
```

### REST API — Advanced Detection

```
POST /api/detect/webrtc?target=example.com        — WebRTC leak detection
GET  /api/detect/webrtc/{target}                   — WebRTC leak detection (GET)

POST /api/detect/fingerprint?target=example.com   — Browser fingerprint detection
GET  /api/detect/fingerprint/{target}              — Browser fingerprint detection (GET)

POST /api/detect/dpi?target=example.com           — DPI system fingerprinting
GET  /api/detect/dpi/{target}                      — DPI fingerprinting (GET)

POST /api/training/retrain                         — Retrain ONNX model
     Body: {
       "model_path": "path/to/model.onnx",
       "attack_results": [...],
       "epochs": 5,
       "learning_rate": 0.001
     }
```

### Prometheus Metrics

```
GET    /metrics                           — Prometheus text exposition
```

Метрики:
- `dynam_campaigns_total{status}` — всего кампаний по статусу
- `dynam_attacks_total{type,status}` — всего атак по типу и результату
- `dynam_stealth_score{target}` — последний stealth score
- `dynam_detection_rate{target}` — detection rate
- `dynam_attack_latency_ms{type}` — средняя latency по типу атаки
- `dynam_poller_targets` — количество таргетов
- `dynam_poller_last_stealth{name}` — последний stealth по таргету
- `dynam_poller_total_runs{name}` — всего запусков по таргету
- `dynam_poller_trend{name}` — тренд (1=improving, 0=stable, -1=degrading)

### WebSocket

```
WS   /ws/{campaign_id}                    — Real-time прогресс
```

Формат сообщений:
```json
{
  "campaign_id": "abc123",
  "status": "running",
  "progress_percent": 45.0,
  "current_attack": "fragment",
  "success_rate": 0.73,
  "avg_stealth": 0.68,
  "detection_rate": 0.27
}
```

## Использование

### Python API — Campaigns

```python
from src.core.attack_manager import AttackManager, CampaignConfig, CampaignMode

manager = AttackManager()

config = CampaignConfig(
    name="test-campaign",
    target="https://example.com",
    mode=CampaignMode.AUTO,
    attacks=["ecs", "fragment", "adversarial_padding"],
    iterations=500,
    intensity=7,
    adaptive=True,
)

campaign_id = await manager.start_campaign(config)

# Wait for completion
while True:
    progress = manager.get_campaign(campaign_id)
    if progress.status.value in ("completed", "stopped"):
        break
    await asyncio.sleep(1)

# Generate report
summary = manager.get_summary(campaign_id)
report_path = report_gen.generate_html_report(summary, progress.results)
```

### Python API — Poller Engine

```python
from src.core.poller_engine import PollerEngine, PollerTarget
from src.core.attack_manager import AttackManager

manager = AttackManager()
poller = PollerEngine(manager, reports_dir="reports")

# Add target
target = PollerTarget(
    name="production-site",
    url="https://example.com",
    schedule_seconds=21600,  # every 6 hours
    attacks=["ecs", "fragment", "adversarial_padding"],
    mode="auto",
    iterations=200,
    min_stealth=0.5,
    notify=["admin@example.com"],
)
poller.add_target(target)

# Start automated engine
await poller.start()

# Check trend
trend = poller.get_trend("production-site", days=7)
print(f"Trend: {trend['trend']}, Avg stealth: {trend['avg']:.2f}")

# Alert if stealth < threshold
for alert in poller.get_alerts():
    print(f"ALERT: {alert['target']} — stealth {alert['current']:.2f} < {alert['threshold']:.2f}")
```

### CLI

```bash
# Запуск кампании
curl -X POST http://localhost:8090/api/campaigns/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "mode": "auto",
    "attacks": ["ecs", "fragment", "adversarial_padding"],
    "iterations": 500,
    "intensity": 7,
    "adaptive": true
  }'

# Добавить poller таргет
curl -X POST http://localhost:8090/api/poller/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-site",
    "url": "https://example.com",
    "schedule_seconds": 21600,
    "attacks": ["ecs", "fragment"],
    "min_stealth": 0.5,
    "notify": ["admin@example.com"]
  }'

# Запустить движок
curl -X POST http://localhost:8090/api/poller/start

# Prometheus метрики
curl http://localhost:8090/metrics

# Получить прогресс
curl http://localhost:8090/api/campaigns/{id}

# Скачать отчёт
curl http://localhost:8090/api/campaigns/{id}/report/html > report.html
```

## WebUI

Откройте http://localhost:3000/auto-attack в браузере.

Функции:
- Выбор цели (URL/домен)
- Выбор режима кампании
- Выбор типов атак
- Настройка параметров (итерации, интенсивность, concurrent)
- Real-time прогресс через WebSocket
- Графики stealth scores
- Таблица результатов
- Скачивание отчётов (HTML/JSON)

## Poller Engine — Автоматическое тестирование

### Концепция

PollerEngine позволяет настроить автоматическое тестирование критических таргетов:
1. Добавляете таргет с расписанием (например, каждые 6 часов)
2. Движок автоматически запускает кампании по расписанию
3. Результаты сохраняются в SQLite
4. Trend analysis показывает улучшение/деградацию
5. Alerts отправляются при падении stealth ниже порога

### Пример использования

**Мониторинг production сайта:**
```python
target = PollerTarget(
    name="production-api",
    url="https://api.example.com",
    schedule_seconds=21600,  # каждые 6 часов
    attacks=["ecs", "fragment", "adversarial_padding"],
    mode="auto",
    iterations=500,
    min_stealth=0.6,
    notify=["ops@example.com", "https://t alerts bot"],
)
```

**Тренд анализ:**
```python
trend = poller.get_trend("production-api", days=30)
# {
#   "count": 120,
#   "avg": 0.72,
#   "min": 0.45,
#   "max": 0.89,
#   "trend": "improving",
#   "latest": 0.81,
#   "earliest": 0.65,
# }
```

### Alerts

Когда stealth падает ниже `min_stealth`:
```
ALERT: production-api — stealth 0.45 < threshold 0.60
       Target: https://api.example.com
       Time: 2025-01-15 14:30:00
```

Уведомления отправляются через:
- Email (если указан email)
- Telegram/Slack webhook (если указан URL)
- stdout (по умолчанию)

## Prometheus & Grafana

### Настройка Prometheus

Добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'dynam-attack-framework'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8090']
    metrics_path: '/metrics'
```

### Настройка Grafana

1. Добавьте Prometheus data source
2. Импортируйте dashboard или создайте новый
3. Используйте запросы:
   - `dynam_stealth_score{target="example.com"}` — stealth score
   - `dynam_attack_latency_ms{type="ecs"}` — latency
   - `dynam_poller_trend{name="production"}` — trend

### Примеры queries

```promql
# Средний stealth за последний час
avg(dynam_stealth_score)

# Detection rate по типам атак
rate(dynam_attacks_total{status="detected"}[1h])

# Trend по таргету
dynam_poller_trend{name="production-site"}

# Latency p95
histogram_quantile(0.95, rate(dynam_attack_latency_ms_bucket[5m]))
```

## Режимы атак

### Single
Запуск одного типа атаки N раз.

### Campaign
Последовательный запуск всех выбранных типов атак.

### Auto-Adaptive
AI выбирает атаки на основе результатов:
- Успешные атаки получают больший вес
- Обнаруженные атаки получают меньший вес
- Автоматическая адаптация к защитным механизмам

### Stress
Параллельный запуск с заданным уровнем конкурентности.

## Метрики

- **Stealth Score** (0-1): 1.0 = невидим для детекторов, 0.0 = полностью обнаружен
- **Detection Probability**: вероятность обнаружения ML-детектором
- **Success Rate**: процент успешных (необнаруженных) атак
- **Latency**: задержка атаки в миллисекундах
- **Trend**: направление изменения (improving/stable/degrading)

## Безопасность

Фреймворк предназначен **только для тестирования собственных систем** или систем с явного разрешения владельца.

Все атаки read-only — не модифицируют целевую систему.

## Интеграция с Dynam

Фреймворк интегрируется с основным Dynam проектом:
- REST API на порту 8090
- WebSocket для real-time обновлений
- React WebUI на /auto-attack
- Отчёты в формате HTML с графиками
- Prometheus метрики для Grafana

## Roadmap

✅ **Все модули реализованы:**

1. ✅ **WebRTC Leak Prevention** — обнаружение WebRTC IP/DNS leaks через STUN, ICE candidates, DNS leaks
2. ✅ **Browser Fingerprint Masking** — детекция Canvas/WebGL/Audio fingerprinting, font enumeration
3. ✅ **Adversarial Training Pipeline** — автоматический retrain ONNX моделей на основе результатов атак
4. ✅ **DPI Fingerprinting** — определение типа DPI системы (Sandvine, Allot, Qosmos, Fortinet, etc.) с auto-select bypass strategies

### Следующие шаги:
- Интеграция с основным Dynam проектом (C++ backend)
- Qt6 GUI для всех модулей
- Grafana dashboards для мониторинга
- Автоматическая генерация рекомендаций на основе DPI fingerprinting

## Лицензия

AGPL-3.0-only
