/** Mirrors `TelemetrySnapshot` from src-tauri/src/metrics.rs */
export interface TelemetrySnapshot {
  seq: number;
  epoch: number;
  clock_skew_us: number;
  egress_queue_depth: number;
  real_frames_sent: number;
  decoy_frames_sent: number;
}

/** Metronome METRICS cadence: one sample every 10 ticks @ 5 ms */
export const TELEMETRY_SAMPLE_INTERVAL_S = 0.05;

export const TELEMETRY_TICK_HZ = 4;
