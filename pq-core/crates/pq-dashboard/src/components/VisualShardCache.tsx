import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Layers, Activity } from "lucide-react";
import type { TelemetrySnapshot } from "../types/telemetry";

interface Shard {
  cid: string;
  data: number[];
  timestamp: number;
}

export function VisualShardCache() {
  const [shards, setShards] = useState<Shard[]>([]);
  const [kernelReady, setKernelReady] = useState(false);
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot | null>(null);
  const kernelReadyRef = useRef(false);

  useEffect(() => {
    kernelReadyRef.current = kernelReady;
  }, [kernelReady]);

  useEffect(() => {
    const loadInitialShards = async () => {
      try {
        const result = await invoke<Shard[]>("get_all_shards");
        setShards(result);
        setKernelReady(true);
      } catch {
        // Expected while kernel is anchoring
      }
    };

    loadInitialShards();

    const unlistenReady = listen("kernel_ready", () => {
      setKernelReady(true);
      loadInitialShards();
    });

    const unlistenShard = listen<string>("shard-arrival", () => {
      if (kernelReadyRef.current) {
        loadInitialShards();
      }
    });

    const unlistenTelemetry = listen<TelemetrySnapshot>("telemetry_tick", (event) => {
      setTelemetry(event.payload);
    });

    return () => {
      unlistenReady.then((fn) => fn());
      unlistenShard.then((fn) => fn());
      unlistenTelemetry.then((fn) => fn());
    };
  }, []);

  return (
    <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex-1 flex flex-col gap-3 min-h-0">
      <h2 className="text-[10px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-2">
        <Layers className="w-3.5 h-3.5" /> Visual Shard Cache (SQLite Persisted)
      </h2>

      <div className="grid grid-cols-3 gap-2 text-[9px] font-mono border border-white/5 rounded-lg p-2 bg-black/30">
        <div className="flex flex-col">
          <span className="text-gray-500 uppercase text-[7px]">Queue Depth</span>
          <span className="text-cyber text-sm">{telemetry?.egress_queue_depth ?? "—"}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-gray-500 uppercase text-[7px]">Real Frames</span>
          <span className="text-amber text-sm">{telemetry?.real_frames_sent ?? "—"}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-gray-500 uppercase text-[7px]">Decoy Frames</span>
          <span className="text-gray-300 text-sm">{telemetry?.decoy_frames_sent ?? "—"}</span>
        </div>
        <div className="col-span-3 flex items-center gap-1 text-[7px] text-gray-600">
          <Activity className="w-3 h-3" />
          4 Hz telemetry_tick · epoch {telemetry?.epoch ?? 0}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar grid grid-cols-2 gap-2 content-start">
        {shards.length === 0 ? (
          <p className="text-[10px] text-gray-600 italic col-span-2">Vault empty...</p>
        ) : (
          shards.map((shard) => {
            const age = Math.floor(Date.now() / 1000) - shard.timestamp;
            const opacity = Math.max(0.2, 1 - age / 3600);

            return (
              <div
                key={shard.cid}
                className="bg-black/40 p-2 rounded-lg border border-white/5 flex flex-col group hover:border-cyber/30 transition-colors"
                style={{ opacity }}
              >
                <span className="font-mono text-[8px] text-amber truncate" title={shard.cid}>
                  {shard.cid}
                </span>
                <div className="flex justify-between items-center mt-1">
                  <span className="text-[6px] text-cyber/60 uppercase font-bold tracking-tighter">
                    EPHEMERAL_V2
                  </span>
                  <span className="text-[7px] text-gray-500 uppercase">
                    {age < 60 ? `${age}s` : `${Math.floor(age / 60)}m`}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
