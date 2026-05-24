import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Layers } from "lucide-react";

interface Shard {
  cid: string;
  data: number[];
  timestamp: number;
}

export function VisualShardCache() {
  const [shards, setShards] = useState<Shard[]>([]);
  const [kernelReady, setKernelReady] = useState(false);

  useEffect(() => {
    const loadInitialShards = async () => {
      try {
        const result = await invoke<Shard[]>("get_all_shards");
        setShards(result);
        setKernelReady(true);
      } catch (e) {
        // Expected if kernel is still anchoring
        console.log("Kernel not ready yet, waiting for signal...");
      }
    };

    // Initial check
    loadInitialShards();

    // Listen for kernel_ready signal
    const unlistenReady = listen("kernel_ready", () => {
      console.log("K-SIGNAL: Kernel Anchored. Unlocking Store.");
      setKernelReady(true);
      loadInitialShards();
    });

    // Real-time Sync: Listen for new shard arrivals from the Rust kernel
    const unlistenShard = listen<string>("shard-arrival", (event) => {
      if (kernelReady) {
        loadInitialShards();
      }
    });

    return () => {
      unlistenReady.then((fn) => fn());
      unlistenShard.then((fn) => fn());
    };
  }, [kernelReady]);

  return (
    <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex-1 flex flex-col gap-3 min-h-0">
      <h2 className="text-[10px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-2">
        <Layers className="w-3.5 h-3.5" /> Visual Shard Cache (SQLite Persisted)
      </h2>
      <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar grid grid-cols-2 gap-2 content-start">
        {shards.length === 0 ? (
          <p className="text-[10px] text-gray-600 italic col-span-2">Vault empty...</p>
        ) : (
          shards.map((shard) => {
            // Calculate age for "Evaporation" simulation
            const age = Math.floor(Date.now() / 1000) - shard.timestamp;
            const opacity = Math.max(0.2, 1 - (age / 3600)); // Persists much longer now (1 hour fade)
            
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
