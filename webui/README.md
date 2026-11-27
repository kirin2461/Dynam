# Dynam WebUI — React + Vite Dashboard

Современный веб-интерфейс для Dynam NCP с реалтайм обновлениями через WebSocket.

## Возможности

- **Dashboard** — обзор всех ключевых метрик
- **Traffic Monitor** — таблица соединений с сортировкой, ONNX-обнаружение
- **Configuration** — настройки ONNX, DPI bypass, proxy, logging
- **Activity Log** — фильтруемые логи с поиском
- **Adversary Tester** — запуск тестов, визуализация прогресса и результатов
- **Statistics** — агрегатные метрики
- **Settings** — переключение языков (RU/EN) и тем (Dark/Light)

## Стек

- **React 18** — UI framework
- **TypeScript** — типизация
- **Vite** — сборка и dev server
- **React Router** — навигация
- **Tailwind CSS** — стилизация (Catppuccin палитра)
- **i18next** — интернационализация
- **Socket.IO Client** — WebSocket
- **Recharts** — графики
- **Lucide React** — иконки

## Структура

```
webui/
├── index.html              # Точка входа
├── package.json            # Зависимости
├── vite.config.ts          # Конфигурация Vite
├── tailwind.config.js      # Конфигурация Tailwind
├── tsconfig.json           # TypeScript конфиг
├── public/
│   └── favicon.svg         # Иконка
└── src/
    ├── main.tsx            # React entry point
    ├── App.tsx             # Роутинг
    ├── styles/
    │   └── globals.css     # Глобальные стили + Tailwind
    ├── components/
    │   ├── Layout.tsx      # Sidebar + навигация
    │   └── StatCard.tsx    # Карточка статистики
    ├── pages/
    │   ├── DashboardPage.tsx
    │   ├── TrafficPage.tsx
    │   ├── ConfigPage.tsx
    │   ├── LogsPage.tsx
    │   ├── AdversaryPage.tsx
    │   ├── StatsPage.tsx
    │   └── SettingsPage.tsx
    ├── hooks/
    │   └── useWebSocket.ts # WebSocket хук
    ├── services/
    │   └── api.ts          # REST API клиент
    ├── locales/
    │   ├── i18n.ts         # i18n конфигурация
    │   ├── ru.json         # Русский перевод
    │   └── en.json         # Английский перевод
    └── types/
        └── index.ts        # TypeScript типы
```

## Установка

```bash
npm install
```

## Разработка

```bash
npm run dev
```

Откроется на http://localhost:3000

Vite настроен с proxy для backend:
- `/api/*` → `http://localhost:8085/api/*`
- `/ws` → `ws://localhost:8085/ws`

## Сборка

```bash
npm run build
```

Результат в `dist/` — готов для деплоя.

## Preview

```bash
npm run preview
```

## Деплой

### Static Hosting (Vercel, Netlify, GitHub Pages)

```bash
npm run build
# Загрузить содержимое dist/ на хостинг
```

### Nginx

```nginx
server {
    listen 80;
    server_name dynam.example.com;
    
    root /var/www/dynam-webui/dist;
    index index.html;
    
    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8085;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
    
    # WebSocket proxy
    location /ws {
        proxy_pass http://127.0.0.1:8085;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

## API Endpoints

WebUI использует те же endpoints, что и Qt6 GUI:

### REST API

- `GET /api/traffic`
- `GET/PUT /api/config`
- `POST /api/adversary/run`
- `GET /api/logs?limit=N`
- `DELETE /api/logs`
- `GET /api/stats`
- `GET /api/health`

### WebSocket

Подключение: `ws://host/ws`

Сообщения:

```typescript
interface WebSocketMessage {
  type: 'traffic' | 'log' | 'status' | 'adversary' | 'stats';
  data: any;
}
```

## Темы

- **Dark** (по умолчанию) — Catppuccin Mocha
- **Light** — Catppuccin Latte

Переключение в Settings → Theme. Сохраняется в `localStorage`.

## i18n

- **Русский** (ru) — по умолчанию
- **English** (en)

Переключение в Settings → Language. Сохраняется в `localStorage`.

## TypeScript типы

Все данные типизированы в `src/types/index.ts`:

```typescript
interface TrafficConnection {
  source: string;
  destination: string;
  protocol: string;
  bytes: number;
  packets: number;
  stealth_score: number;
  onnx_detected: boolean;
  onnx_probability: number;
  status: string;
}

interface AppConfig { ... }
interface LogEntry { ... }
interface AdversaryTestParams { ... }
interface AdversaryTestResults { ... }
interface AppStats { ... }
```

## Лицензия

AGPL-3.0-only
