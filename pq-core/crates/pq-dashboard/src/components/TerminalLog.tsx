import React, { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import type { TelemetrySnapshot } from "../types/telemetry";

export const TerminalLog: React.FC = () => {
  const [logs, setLogs] = useState<string[]>([]);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setLogs((prev) => [
      ...prev,
      "> System initialized",
      "> Awaiting telemetry_tick (4 Hz Seqlock pump)...",
    ]);

    const unlistenLog = listen<string>("system-log", (event) => {
      setLogs((prev) => [...prev.slice(-49), "> " + event.payload]);
    });

    const unlistenErr = listen<string>("system-error", (event) => {
      setLogs((prev) => [...prev.slice(-49), "!! ERR: " + event.payload]);
    });

    const unlistenTelemetry = listen<TelemetrySnapshot>("telemetry_tick", (event) => {
      const t = event.payload;
      const line =
        `[TELEMETRY] seq:${t.seq} epoch:${t.epoch} ` +
        `skew_us:${t.clock_skew_us} queue:${t.egress_queue_depth} ` +
        `real:${t.real_frames_sent} decoy:${t.decoy_frames_sent}`;
      setLogs((prev) => [...prev.slice(-49), "> " + line]);
    });

    return () => {
      unlistenLog.then((u) => u());
      unlistenErr.then((u) => u());
      unlistenTelemetry.then((u) => u());
    };
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="w-full h-full flex flex-col font-mono text-[10px] text-[#00FF41] overflow-hidden p-2">
      <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col gap-0.5">
        {logs.map((log, i) => (
          <div key={i} className="opacity-80 hover:opacity-100">
            {log}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </div>
  );
};
