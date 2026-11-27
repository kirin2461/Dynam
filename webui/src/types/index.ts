// Traffic types
export interface TrafficConnection {
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

export interface TrafficData {
  connections: TrafficConnection[];
  total_bytes: number;
  total_packets: number;
}

// Config types
export interface AppConfig {
  onnx_model_path: string;
  onnx_threshold: number;
  onnx_weight: number;
  onnx_enabled: boolean;
  dpi_strategy: string;
  auto_rotate: boolean;
  proxy_host: string;
  proxy_port: number;
  log_level: number;
  log_retention_days: number;
}

// Log types
export interface LogEntry {
  timestamp: string;
  level: number;
  source: string;
  message: string;
}

export enum LogLevel {
  Debug = 0,
  Info = 1,
  Warning = 2,
  Error = 3,
  Critical = 4,
}

// Adversary Tester types
export interface AdversaryTestParams {
  attack_type: string;
  iterations: number;
  intensity: number;
}

export interface AdversaryTestResults {
  avg_stealth: number;
  min_stealth: number;
  max_stealth: number;
  detection_rate: number;
  onnx_detection_rate: number;
  onnx_confidence: number;
  total_attacks?: number;
  successful?: number;
  success_rate?: number;
  campaign_id?: string;
}

// Stats types
export interface AppStats {
  total_bytes: number;
  total_packets: number;
  total_connections: number;
  avg_bandwidth: number;
  avg_stealth: number;
  min_stealth: number;
  max_stealth: number;
  median_stealth: number;
  onnx_inferences: number;
  onnx_detections: number;
  onnx_detection_rate: number;
  onnx_avg_confidence: number;
  total_attacks: number;
  successful_attacks: number;
  attack_success_rate: number;
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'traffic' | 'log' | 'status' | 'adversary' | 'stats';
  data: any;
}
