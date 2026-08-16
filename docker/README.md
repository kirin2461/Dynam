# Dynam Integration Testbed (docker/)

Изолированный стенд «клиент vs DPI» для боевого тестирования всех функций
проекта без риска уронить сеть хост-машины. Оба контейнера живут в приватной
bridge-сети `172.30.0.0/24`; `NET_ADMIN`/`NET_RAW` действуют только внутри
контейнеров — iptables/DNS хоста не затрагиваются.

## Состав

| Контейнер | Адрес | Роль |
|---|---|---|
| `dynam-dpi`    | 172.30.0.10 | DPI-эмулятор: HTTPS/HTTP сервер + RST-инъекция по SNI/Host для заблокированных доменов (iptables string match, как реальный inline-DPI). Опционально `tc netem` (delay/loss). |
| `dynam-client` | 172.30.0.20 | Собранный из репо `ncp` CLI + матрица боевых тестов `scripts/testbed/run_integration.sh`. |

Заблокированные домены (env `BLOCKED_DOMAINS`): `forbidden.example`, `blocked.example`.
Контрольный: `allowed.example` — всегда доступен (регрессионная проверка).

## Запуск

```bash
docker compose build
docker compose up -d dpi
docker compose run --rm client     # полная матрица; exit 0 = всё зелёное
docker compose down -v
```

## Что проверяет матрица

- **A. CLI sanity**: version/help, crypto (hash sha256/blake2b/sha512, keygen,
  sign/verify), license hwid/info, network interfaces/info, import-zapret,
  sysproxy status.
- **B. Baseline**: без обхода заблокированные домены получают RST (TLS+HTTP),
  allowed — доступен.
- **C. Proxy presets**: tspu/beeline/mts/megafon/tele2/mobile/auto против
  заблокированных и контрольного домена.
- **D. Zapret-профили**: zapret_full/general/tcp/quic + опции
  --block-quic/--fake-quic + импортированный zapret-профиль.
- **E. dpi mode**: наличие и справка команды.
- **F. blockcheck**: автовыбор стратегии (Geneva engine) по живым доменам.
- **G. autopilot**: learn/status/reset по заблокированному домену.
- **H. mimicry**: http/https/quic/websocket/skype/zoom/bittorrent/random через
  прокси к контрольному домену.
- **I. lifecycle**: rotate, status, stop.

## Переопределение матрицы

```bash
docker compose run --rm -e PRESETS="tspu auto" \
  -e ZAPRET_PROFILES="zapret_full" -e MIMIC_MODES="https quic" client
```

Импэрмент канала (в `docker-compose.yml`, сервис `dpi`):

```yaml
environment:
  DPI_NETEM: "delay 80ms loss 2%"
```

CI: `.github/workflows/integration-testbed.yml` прогоняет стенд на каждый PR,
затрагивающий `src/`, `docker/`, `scripts/testbed/`.
