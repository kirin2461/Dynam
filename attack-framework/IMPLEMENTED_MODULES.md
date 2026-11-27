# Attack Framework — Все реализованные модули

## ✅ Полностью реализовано

### 1. WebRTC Leak Prevention
**Файл:** `src/attacks/webrtc_leak.py`

**Обоснование:** WebRTC может раскрывать реальный IP через STUN requests, обходя прокси/VPN.

**Возможности:**
- STUN request analysis — обнаружение outbound STUN traffic
- ICE candidate inspection — проверка real IP в candidates
- DNS leak detection — проверка DNS queries
- TURN server validation — проверка использования TURN relay

**API:**
```
POST /api/detect/webrtc?target=example.com
GET  /api/detect/webrtc/{target}
```

**Результат:**
- `leak_detected: bool` — обнаружены ли утечки
- `leaked_ips: list` — список утёкших IP
- `severity: none|low|medium|high|critical`

---

### 2. Browser Fingerprint Masking
**Файл:** `src/attacks/browser_fingerprint.py`

**Обоснование:** Browser fingerprinting использует Canvas, WebGL, Audio APIs для создания уникальных идентификаторов.

**Возможности:**
- Canvas fingerprint detection — обнаружение canvas.toDataURL() с уникальными паттернами
- WebGL fingerprint detection — обнаружение GPU vendor/renderer string harvesting
- Audio fingerprint detection — обнаружение AudioContext fingerprinting
- Font enumeration detection — обнаружение font detection attempts
- Plugin enumeration detection — обнаружение plugin list harvesting

**API:**
```
POST /api/detect/fingerprint?target=example.com
GET  /api/detect/fingerprint/{target}
```

**Результат:**
- `fingerprint_detected: bool` — обнаружено ли fingerprinting
- `canvas_fingerprint: bool` — canvas fingerprinting
- `webgl_fingerprint: bool` — WebGL fingerprinting
- `audio_fingerprint: bool` — audio fingerprinting
- `font_enumeration: int` — количество проbed fonts
- `fingerprint_hash: str` — хэш fingerprint

---

### 3. Adversarial Training Pipeline
**Файл:** `src/training/adversarial_training.py`

**Обоснование:** Автоматический retrain ONNX моделей на основе результатов атак для улучшения robustness.

**Pipeline:**
1. Сбор attack samples из результатов кампаний
2. Генерация adversarial examples из успешных атак
3. Аугментация training dataset
4. Retraining ONNX моделей
5. Оценка улучшенной robustness

**API:**
```
POST /api/training/retrain
Body: {
  "model_path": "path/to/model.onnx",
  "attack_results": [...],
  "epochs": 5,
  "learning_rate": 0.001
}
```

**Результат:**
- `training_samples: int` — количество samples для training
- `adversarial_samples: int` — количество сгенерированных adversarial samples
- `pre_accuracy: float` — accuracy до retraining
- `post_accuracy: float` — accuracy после retraining
- `robustness_improvement: float` — улучшение robustness
- `new_model_path: str` — путь к новой модели

---

### 4. DPI Fingerprinting
**Файл:** `src/attacks/dpi_fingerprint.py`

**Обоснование:** Определение типа DPI системы для auto-select оптимальных стратегий обхода.

**DPI системы:**
- Sandvine — weak HTTP parsing, vulnerable to header obfuscation
- Allot — strict protocol validation, weak against fragmentation
- Qosmos — ML-based, vulnerable to adversarial padding
- nPuls — timing-based detection, weak against timing manipulation
- Fortinet — certificate pinning issues, weak against TLS splitting
- Palo Alto — ML-based detection
- Cisco — protocol validation

**Detection methods:**
- Response pattern analysis — DPI-specific error messages
- TCP behavior analysis — TCP stack modifications
- TLS fingerprinting — TLS inspection patterns
- HTTP parsing quirks — HTTP parser behavior
- Protocol support analysis — protocol limitations

**API:**
```
POST /api/detect/dpi?target=example.com
GET  /api/detect/dpi/{target}
```

**Результат:**
- `dpi_detected: bool` — определена ли DPI система
- `dpi_system: str` — sandvine|allot|qosmos|npuls|fortinet|palo_alto|cisco|custom
- `confidence: float` — уверенность (0-1)
- `bypass_strategies: list` — рекомендованные стратегии обхода
- `characteristics: dict` — характеристики DPI системы

---

## Интеграция

### API Endpoints
**Всего:** 32 endpoints

**Новые endpoints (10):**
- `POST /api/detect/webrtc?target=...`
- `GET /api/detect/webrtc/{target}`
- `POST /api/detect/fingerprint?target=...`
- `GET /api/detect/fingerprint/{target}`
- `POST /api/detect/dpi?target=...`
- `GET /api/detect/dpi/{target}`
- `POST /api/training/retrain`

### Файлы
```
attack-framework/
├── src/
│   ├── attacks/
│   │   ├── implementations.py        # 7 базовых атак
│   │   ├── webrtc_leak.py            # NEW: WebRTC leak detection
│   │   ├── browser_fingerprint.py    # NEW: Browser fingerprinting detection
│   │   └── dpi_fingerprint.py        # NEW: DPI system fingerprinting
│   ├── training/
│   │   └── adversarial_training.py   # NEW: Auto-retrain ONNX models
│   ├── core/
│   │   ├── attack_manager.py
│   │   ├── poller_engine.py          # Scheduled testing
│   │   └── prometheus_export.py      # Prometheus metrics
│   ├── api/
│   │   ├── server.py
│   │   ├── poller_routes.py          # Poller & Prometheus API
│   │   └── advanced_routes.py        # NEW: Advanced modules API
│   └── reports/
│       └── report_generator.py
└── requirements.txt
```

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

## Статистика

- **Всего модулей:** 11 (7 базовых атак + 4 advanced)
- **API endpoints:** 32
- **Строки кода:** ~3,500
- **Новые файлы:** 4 (webrtc_leak.py, browser_fingerprint.py, dpi_fingerprint.py, adversarial_training.py, advanced_routes.py)

---

## Следующие шаги

1. **Интеграция с Dynam C++ backend** — вызов Python API из C++ через pybind11
2. **Qt6 GUI** — виджеты для всех advanced модулей
3. **Grafana dashboards** — визуализация всех метрик
4. **Автоматическая генерация рекомендаций** — на основе DPI fingerprinting
5. **Batch processing** — массовое тестирование множества целей

---

## Лицензия

AGPL-3.0-only
