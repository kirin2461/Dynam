import { useEffect, useRef, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { getToken } from '@/services/api';
import type { WebSocketMessage, TrafficData, LogEntry, AppStats, AdversaryTestResults } from '@/types';

interface UseWebSocketOptions {
  url?: string;
  autoConnect?: boolean;
  reconnectAttempts?: number;
  reconnectDelay?: number;
}

interface UseWebSocketReturn {
  connected: boolean;
  traffic: TrafficData | null;
  logs: LogEntry[];
  stats: AppStats | null;
  adversaryUpdate: { progress: number; status: string; results?: AdversaryTestResults } | null;
  sendMessage: (type: string, data: any) => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
  const {
    url = window.location.origin,
    autoConnect = true,
    reconnectAttempts = 10,
    reconnectDelay = 1000,
  } = options;

  const [connected, setConnected] = useState(false);
  const [traffic, setTraffic] = useState<TrafficData | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stats, setStats] = useState<AppStats | null>(null);
  const [adversaryUpdate, setAdversaryUpdate] = useState<any>(null);

  const socketRef = useRef<Socket | null>(null);
  const reconnectCountRef = useRef(0);

  const connect = useCallback(() => {
    if (socketRef.current?.connected) return;

    // Auth token is required by the /ws namespace connect handler.
    void (async () => {
      const token = (await getToken().catch(() => null)) || '';
      if (socketRef.current?.connected) return;

      socketRef.current = io(url, {
        transports: ['polling'],
        auth: { token },
        reconnection: true,
        reconnectionAttempts: reconnectAttempts,
        reconnectionDelay: reconnectDelay,
      });

      socketRef.current.on('connect', () => {
        setConnected(true);
        reconnectCountRef.current = 0;
      });

      socketRef.current.on('disconnect', () => {
        setConnected(false);
      });

      socketRef.current.on('connect_error', (error) => {
        console.error('WebSocket error:', error);
      });

      socketRef.current.on('message', (msg: WebSocketMessage) => {
        switch (msg.type) {
          case 'traffic':
            setTraffic(msg.data);
            break;
          case 'log':
            setLogs(prev => [...prev.slice(-999), msg.data]);
            break;
          case 'stats':
            setStats(msg.data);
            break;
          case 'adversary':
            setAdversaryUpdate(msg.data);
            break;
        }
      });
    })();
  }, [url, reconnectAttempts, reconnectDelay]);

  const sendMessage = useCallback((type: string, data: any) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('message', { type, data });
    }
  }, []);

  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      socketRef.current?.disconnect();
    };
  }, [autoConnect, connect]);

  return {
    connected,
    traffic,
    logs,
    stats,
    adversaryUpdate,
    sendMessage,
  };
}
