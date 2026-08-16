# Dynam Integration Testbed (docker/)

Изолированный стенд «клиент → DPI-мидбокс → сервер» для боевого тестирования
всех функций проекта без риска уронить сеть хост-машины. Три контейнера живут
в двух приватных bridge-сетях (`172.30.1.0/24` clientnet, `172.30.2.0/24`
servernet); `NET_ADMIN`/`NET_RAW` действуют только внутри контейнеров —
iptables/DNS хоста не затрагиваются.

## Топология

```
 client (172.30.1.20) ── clientnet ──► dpi router (172.30.1.10 / 172.30.2.10)
                                        ── servernet ──► target (172.30.2.30)
```

DPI — это настоящий **мидбокс**, а не сервер: он форвардит трафик и шлёт
TCP RST на любой пакет с заблокированным SNI/Host (iptables `-m string`,
по-пакетно — как операторский inline-DPI). Поэтому fake/desync-пакеты умирают
на мидбоксе и никогда не «отравляют» целевой сервер, а сплит-пакетные техники
обходят блокировку по-настоящему. На всех интерфейсах стенда отключены
GRO/TSO/GSO (иначе veth склеивает сегменты до netfilter).

## Состав

| Контейнер     | Адреса                      | Роль |
|---|---|---|
| `dynam-dpi`    | 172.30.1.10 / 172.30.2.10 | DPI-мидбокс: ip_forward + RST-инъекция по SNI/Host (FORWARD, string match) + MASQUERADE. Опционально `tc netem` (delay/loss). |
| `dynam-target` | 172.30.2.30               | Целевой HTTPS/HTTP сервер с маркером `DYNAM-TESTBED-OK` (потоковый TLS-сервер с ленивым handshake — устойчив к повреждённым desync-соединениям). |
| `dynam-client` | 172.30.1.20               | Собранный из репо `ncp` CLI + матрица боевых тестов `scripts/testbed/run_integration.sh`. Маршрут к servernet — через мидбокс. |

Заблокированные домены (env `BLOCKED_DOMAINS`): `forbidden.example`, `blocked.example`.
Контрольный: `allowed.example` — всегда доступен (регрессионная проверка).

## Запуск

```bash
docker compose build
docker compose up -d --wait dpi server
docker compose run --rm client     # полная матрица; exit 0 = всё зелёное
docker compose down -v
```

## Что проверяет матрица

- **A. CLI sanity**: version/help, crypto (hash sha256/blake2b/sha512, keygen,
  sign/verify), license hwid/info, network interfaces/info, import-zapret,
  sysproxy status.
- **B. Baseline**: без обхода blocked-домены получают RST (TLS SNI и HTTP Host),
  allowed — доступен.
- **B2. run mode**: полный стек защиты внутри контейнера (kill switch никогда
  не включается), после `stop` baseline восстанавливается.
- **C. proxy presets**: tspu/beeline/mts/megafon/tele2/mobile/auto ×
  blocked/allowed. Гейт: allowed всегда работает; tspu (zapret
  `--split-pos=1,midsld`) обязан обходить DPI. Остальные пресеты —
  информационно (в их стратегиях пока нет midsld-позиций).
- **C2. inline zapret chain**: `--chain "--dpi-desync=multisplit
  --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq"` — эталонный
  обход string-match DPI (гейт).
- **D. zapret profiles**: zapret_full/general/tcp/quic + QUIC-опции
  (hostlist-scoped — обход forbidden информационный, allowed — гейт).
- **E. dpi mode**: smoke десинк-прокси (фон + таймаут; `--help` у `ncp dpi`
  запускает bypass, поэтому так).
- **F. blockcheck**: авто-подбор стратегии (Geneva) — в пространстве есть
  split-midsld/multisplit-1-midsld, лучшая стратегия обязана найтись.
- **G. autopilot**: самообучение learn/status/reset.
- **H. mimicry**: http/https/quic/websocket/skype/zoom/bittorrent/random через
  прокси — allowed доступен.
- **I. lifecycle**: rotate/status/stop.

Выходной код 0 только если все гейты зелёные; `[INFO]`-провалы (ожидаемые
не-обходы) на результат не влияют.
