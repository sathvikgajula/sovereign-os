import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import type { TelemetrySnapshot } from "../types/telemetry";

export function useTelemetry() {
  const [snapshot, setSnapshot] = useState<TelemetrySnapshot | null>(null);
  const [history, setHistory] = useState<TelemetrySnapshot[]>([]);

  useEffect(() => {
    const unlisten = listen<TelemetrySnapshot>("telemetry_tick", (event) => {
      const sample = event.payload;
      setSnapshot(sample);
      setHistory((prev) => [...prev.slice(-119), sample]);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  return { snapshot, history };
}
