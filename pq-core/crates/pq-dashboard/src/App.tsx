import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { MeshGraph } from "./components/MeshGraph";
import { Shield, Send, Terminal, Zap, Trash2, Mail } from "lucide-react";

interface Peer {
  peer_did: string;
  alpha: number;
  beta: number;
  last_interaction: number;
}

function App() {
  const [peers, setPeers] = useState<Peer[]>([]);
  const [recipient, setRecipient] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("System Optimal");
  const [inventory, setInventory] = useState<string[]>([]);

  useEffect(() => {
    const interval = setInterval(refreshStats, 2000);
    return () => clearInterval(interval);
  }, []);

  async function refreshStats() {
    try {
      const stats = await invoke<{ peers: Peer[] }>("get_mesh_stats");
      setPeers(stats.peers);
      const inv = await invoke<string[]>("get_storage_inventory");
      setInventory(inv);
    } catch (e) {
      setStatus("Network Obstructed");
    }
  }

  async function sendMessage() {
    if (!recipient || !message) return;
    setStatus("Shattering...");
    try {
      const res = await invoke<string>("send_sovereign_message", { 
        recipientDid: recipient, 
        payload: message 
      });
      setStatus(res);
      setMessage("");
    } catch (e) {
      setStatus("Routing Failure");
    }
  }

  async function chaosSlash(did: string) {
    try {
      await invoke("trigger_chaos_simulation", { peerDid: did, slash: true });
      refreshStats();
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className="flex flex-col h-screen w-screen p-6 bg-[#0d0d0d] text-gray-200 overflow-hidden font-sans">
      {/* Header */}
      <header className="flex justify-between items-center mb-8">
        <div className="flex items-center gap-3">
          <div className="bg-pq-green/20 p-2 rounded-lg">
            <Shield className="text-pq-green w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">Sovereign Interface</h1>
            <p className="text-xs text-pq-green/60 font-mono italic">Phase 5: Armored Mesh v2.0</p>
          </div>
        </div>
        <div className="flex items-center gap-6 text-xs font-mono">
          <div className="flex flex-col items-end">
            <span className="text-gray-500 uppercase tracking-widest">Network Status</span>
            <span className={status === "System Optimal" ? "text-pq-green" : "text-pq-red animate-pulse"}>
              {status}
            </span>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="grid grid-cols-12 gap-6 flex-1 min-h-0">
        
        {/* Left: Mesh Visualization */}
        <section className="col-span-8 flex flex-col gap-4 relative">
          <div className="flex justify-between items-end px-2">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-500 flex items-center gap-2">
              <Zap className="w-4 h-4" /> Trust Mesh Visualization
            </h2>
            <span className="text-[10px] text-gray-600 font-mono">Real-time Physical Clustering</span>
          </div>
          <div className="flex-1 min-h-0 bg-white/5 border border-white/10 rounded-2xl overflow-hidden shadow-2xl relative">
            <MeshGraph peers={peers} />
            
            {/* Legend Overlay */}
            <div className="absolute bottom-4 left-4 flex flex-col gap-2 p-3 bg-black/60 backdrop-blur-md rounded-lg border border-white/5 text-[10px]">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-pq-green shadow-[0_0_8px_#10b981]" />
                <span className="text-white">The Sanctuary (E[R] &gt; 0.9)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-pq-gray" />
                <span className="text-gray-400">The Fringe (E[R] &gt; 0.4)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-pq-red" />
                <span className="text-pq-red">The Severed (E[R] &lt; 0.4)</span>
              </div>
            </div>
          </div>
        </section>

        {/* Right: Controls & Messenger */}
        <section className="col-span-4 flex flex-col gap-6">
          
          {/* Armored Messenger */}
          <div className="bg-white/5 border border-white/10 rounded-2xl p-5 flex flex-col gap-4">
             <h2 className="text-xs font-bold uppercase tracking-widest text-gray-400 flex items-center gap-2">
               <Send className="w-3.5 h-3.5" /> Armored Messenger
             </h2>
             <div className="flex flex-col gap-3">
               <input 
                 type="text" 
                 placeholder="Recipient DID"
                 className="bg-black border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-pq-green/50 placeholder:text-gray-700"
                 value={recipient}
                 onChange={e => setRecipient(e.target.value)}
               />
               <textarea 
                 placeholder="Sovereign Payload..."
                 rows={3}
                 className="bg-black border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-pq-green/50 placeholder:text-gray-700 resize-none"
                 value={message}
                 onChange={e => setMessage(e.target.value)}
               />
               <button 
                 onClick={sendMessage}
                 className="bg-pq-green/10 hover:bg-pq-green/20 text-pq-green border border-pq-green/30 py-3 rounded-lg text-sm font-bold transition-all flex items-center justify-center gap-2 active:scale-[0.98]"
               >
                 Initiate Sphinx Route
               </button>
             </div>
             
             {/* Seedless Recovery Mock */}
             <button className="flex items-center justify-center gap-2 text-[10px] text-gray-500 hover:text-gray-300 transition-colors py-2 border border-dashed border-white/10 rounded-lg mt-1 group">
               <Mail className="w-3 h-3 group-hover:scale-110 transition-transform" /> Recover via Email (ZK-MPC Mock)
             </button>
          </div>

          {/* Storage & Chaos */}
          <div className="flex-1 min-h-0 flex flex-col gap-4 overflow-hidden">
             
             {/* Storage Inventory */}
             <div className="bg-white/5 border border-white/10 rounded-2xl p-5 flex-1 flex flex-col gap-3 overflow-hidden">
                <h2 className="text-xs font-bold uppercase tracking-widest text-gray-400 flex items-center gap-2">
                  <Trash2 className="w-3.5 h-3.5" /> Ephemeral Shards ({inventory.length})
                </h2>
                <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                  {inventory.length === 0 ? (
                    <p className="text-[10px] text-gray-600 italic">Cache currently clean...</p>
                  ) : (
                    <ul className="flex flex-col gap-2">
                      {inventory.map(cid => (
                        <li key={cid} className="flex items-center justify-between bg-black/40 p-2 rounded border border-white/5 group">
                          <span className="font-mono text-[9px] text-gray-500 truncate">{cid}</span>
                          <span className="text-[8px] bg-pq-green/10 text-pq-green px-1.5 py-0.5 rounded uppercase font-bold">RAM</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
             </div>

             {/* Chaos Simulation */}
             <div className="bg-pq-red/5 border border-pq-red/20 rounded-2xl p-5 shrink-0">
                <h2 className="text-xs font-bold uppercase tracking-widest text-pq-red/80 flex items-center gap-2 mb-3">
                  <Terminal className="w-3.5 h-3.5" /> Chaos Debugger
                </h2>
                <div className="flex flex-col gap-2">
                  <button 
                    onClick={() => { if(peers.length > 0) chaosSlash(peers[0].peer_did) }}
                    className="w-full bg-pq-red/10 hover:bg-pq-red/20 text-pq-red border border-pq-red/20 py-2 rounded text-[10px] uppercase font-bold transition-all"
                  >
                    Slash Nearest Node (Slash Trial)
                  </button>
                </div>
             </div>
          </div>

        </section>
      </main>

      {/* Footer / Credits */}
      <footer className="mt-8 flex justify-between items-center px-2">
        <span className="text-[10px] text-gray-700 font-mono">Sovereign Mesh Access v2.0.42</span>
        <div className="flex gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-pq-green animate-pulse" />
            <span className="text-[9px] uppercase tracking-tighter text-pq-green/80">CSPRNG Pad Active</span>
          </div>
          <div className="flex items-center gap-1.5">
             <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
             <span className="text-[9px] uppercase tracking-tighter text-blue-500/80">Sphinx v1.1.0-nested</span>
          </div>
        </div>
      </footer>

      <style dangerouslySetInnerHTML={{ __html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.05); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.1); }
      `}} />
    </div>
  );
}

export default App;
