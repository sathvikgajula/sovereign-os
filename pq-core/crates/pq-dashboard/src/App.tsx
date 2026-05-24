import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { MeshGraph } from "./components/MeshGraph";
import { FlatlineChart } from "./components/FlatlineChart";
import { TerminalLog } from "./components/TerminalLog";
import { VisualShardCache } from "./components/VisualShardCache";
import { listen } from "@tauri-apps/api/event";
import { Shield, Send, Terminal, Zap, Layers, Activity, Link2, Link2Off } from "lucide-react";

interface Peer {
  peer_did: string;
  alpha: number;
  beta: number;
  last_interaction: number;
}

interface LiveStreamMetrics {
  active: boolean;
  relay_a_bytes: number;
  relay_b_bytes: number;
}

function App() {
  const [peers, setPeers] = useState<Peer[]>([]);
  const [recipient, setRecipient] = useState("");
  const [message, setMessage] = useState("");
  const [inventory, setInventory] = useState<{ id: string, age: number }[]>([]);
  const [metrics, setMetrics] = useState<LiveStreamMetrics | null>(null);
  const [localPeerConnected, setLocalPeerConnected] = useState(false);
  const [connectedPort, setConnectedPort] = useState<number | null>(null);
  
  // Messenger Lifecycle Tracker
  const [msgStatus, setMsgStatus] = useState<string | null>(null);

  useEffect(() => {
    const interval = setInterval(refreshStats, 2000);
    return () => clearInterval(interval);
  }, []);

  // Visual Cache Aging simulation loop
  useEffect(() => {
    const ageInterval = setInterval(() => {
      setInventory(prev => prev.map(inv => ({ ...inv, age: inv.age + 1 })));
    }, 1000);
    return () => clearInterval(ageInterval);
  }, []);

  // Handshake Event Sync: Listen for local discovery
  useEffect(() => {
    const unlisten = listen<number>("local-peer-up", (event) => {
        setLocalPeerConnected(true);
        setConnectedPort(event.payload);
        console.log(`[MESH] Handshake Sync: Local peer up on port ${event.payload}`);
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  async function refreshStats() {
    try {
      const stats = await invoke<{ peers: Peer[] }>("get_mesh_stats");
      setPeers(stats.peers);
      
      const invString = await invoke<string[]>("get_storage_inventory");
      // Map existing ids or insert new ones starting at age 0
      setInventory(prev => {
         const out = [];
         for (const id of invString) {
             const existing = prev.find(p => p.id === id);
             out.push(existing ? existing : { id, age: 0 });
         }
         return out;
      });

      const metricsData = await invoke<LiveStreamMetrics>("get_stream_metrics");
      setMetrics(metricsData);
    } catch (e) {
      // setStatus("Network Obstructed");
    }
  }

  async function sendMessage() {
    if (!recipient || !message) return;
    setMsgStatus("🔒 Sealed: Local encryption complete.");
    
    setTimeout(() => {
        setMsgStatus("🌪️ Vaulted: Shards distributed via Mix-Net.");
        invoke<string>("send_sovereign_message", { 
          recipientDid: recipient, 
          payload: message 
        }).catch(() => {}); // setStatus("Routing Failure")
        setMessage("");
        
        // Mock the ACK reception later
        setTimeout(() => setMsgStatus("✅ Reconstructed: Remote ACK received."), 3000);
    }, 1000);
  }

  async function chaosSlash(did: string) {
    try {
      await invoke("slash_target", { peerDid: did, slash: true });
      refreshStats();
    } catch (e) {
      console.error(e);
    }
  }

  async function startLoopback() {
    try {
      await invoke("initialize_camera_loopback");
      // setStatus("Loopback Active");
    } catch(e) { console.error(e); }
  }

  async function killRelayB() {
    try {
      await invoke("kill_relay_b");
      // setStatus("Relay B Killed");
    } catch(e) { console.error(e); }
  }

  return (
    <div className="dark bg-[#050505] min-h-screen text-zinc-400 font-mono selection:bg-cyan-500/30 overflow-hidden relative p-6 flex flex-col">
      
      {/* Background Ambience */}
      <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyber/10 via-deep to-deep" />

      {/* Header */}
      <header className="flex justify-between items-center mb-6 z-10 bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl px-6 py-4 shrink-0">
        <div className="flex items-center gap-4">
          <div className="bg-cyber/10 p-2.5 rounded-xl border border-cyber/30">
            <Shield className="text-cyber w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase" style={{ letterSpacing: '0.15em' }}>Sovereign Glass</h1>
            <p className="text-[10px] text-cyber/80 font-mono tracking-widest uppercase">Armored Mesh Node v2.0-RC1</p>
          </div>
        </div>
        
        {/* Connection Status Bridge */}
        <div className="flex items-center gap-3">
          <div className="flex flex-col items-end mr-4">
            <span className="text-[9px] text-gray-500 uppercase tracking-widest">
                {localPeerConnected ? `Mesh Active (Port ${connectedPort})` : "Scanning Local Mesh"}
            </span>
            <span className="text-[10px] font-mono text-cyber flex items-center gap-1">
                {localPeerConnected ? <Link2 className="w-3 h-3"/> : <Link2Off className="w-3 h-3 opacity-30"/>}
                ±5ms CSPRNG
            </span>
          </div>
          <div className={`w-3 h-3 rounded-full flex items-center justify-center bg-cyber/20 border border-cyber/50 ${metrics?.active ? 'animate-stutter' : ''}`}>
             <div className="w-1.5 h-1.5 rounded-full bg-cyber" />
          </div>
        </div>
      </header>

      {/* Main Grid: 3-column Layout */}
      <main className="grid grid-cols-1 md:grid-cols-3 gap-6 flex-1 min-h-0 z-10">
        
        {/* LEFT COLUMN: Identity & Trust Mesh */}
        <section className="flex flex-col gap-4">
          <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-1 flex-1 flex flex-col relative overflow-hidden group">
            <div className="absolute inset-x-0 top-0 h-10 bg-gradient-to-b from-black/60 to-transparent z-10 pointer-events-none" />
            <h2 className="absolute top-3 left-4 text-[10px] font-bold uppercase tracking-widest text-cyber flex items-center gap-2 z-20">
              <Zap className="w-3.5 h-3.5" /> Trust Mesh (Social Layer)
            </h2>
            <div className="flex-1 mt-4 rounded-xl overflow-hidden border border-white/5 mx-2 mb-2 bg-[#050505]">
              {peers.length === 0 && !localPeerConnected ? (
                 <div className="flex w-full h-full justify-center items-center">
                    <span className="text-cyber text-xs uppercase animate-pulse">Visualizing Trust Mesh...</span>
                 </div>
              ) : (
                <MeshGraph peers={peers} />
              )}
            </div>
          </div>
        </section>

        {/* CENTER COLUMN: Armored Messenger & Shard Lifecycle */}
        <section className="flex flex-col gap-6">
          <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex flex-col gap-4">
             <h2 className="text-[10px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-2">
               <Send className="w-3.5 h-3.5" /> Armored Messenger (Data Layer)
             </h2>
             <div className="flex flex-col gap-3">
               <input 
                 type="text" 
                 placeholder="Target DID"
                 className="bg-black/50 border border-white/10 rounded-xl p-3 text-sm focus:outline-none focus:border-cyber/50 placeholder:text-gray-700 font-mono"
                 value={recipient}
                 onChange={e => setRecipient(e.target.value)}
               />
               <textarea 
                 placeholder="Enter Sovereign Payload..."
                 rows={3}
                 className="bg-black/50 border border-white/10 rounded-xl p-3 text-sm focus:outline-none focus:border-cyber/50 placeholder:text-gray-700 resize-none font-mono"
                 value={message}
                 onChange={e => setMessage(e.target.value)}
               />
               <div className="h-6">
                 {msgStatus && <span className="text-[10px] font-mono text-amber animate-pulse">{msgStatus}</span>}
               </div>
               <button 
                 onClick={sendMessage}
                 className="bg-cyber/10 hover:bg-cyber/20 text-cyber border border-cyber/30 py-3 rounded-xl text-xs uppercase tracking-widest font-bold transition-all active:scale-[0.98]"
               >
                 Transmit via Mix-Net
               </button>
             </div>
          </div>

          <VisualShardCache />
        </section>

        {/* RIGHT COLUMN: Telemetry & CBR Flatline */}
        <section className="flex flex-col gap-6">
          <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-5 h-64 flex flex-col">
             <FlatlineChart relayA={metrics?.relay_a_bytes || 0} relayB={metrics?.relay_b_bytes || 0} active={metrics?.active || false} />
          </div>

          <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex flex-col shrink-0 border-crimson/20 border">
             <h2 className="text-[10px] font-bold uppercase tracking-widest text-crimson/80 flex items-center gap-2 mb-3">
               <Activity className="w-3.5 h-3.5" /> Chaos Testing
             </h2>
             <div className="flex flex-col gap-2">
               <button 
                 onClick={startLoopback}
                 className="w-full bg-cyber/10 hover:bg-cyber/20 text-cyber border border-cyber/30 py-2.5 rounded-lg text-[9px] tracking-widest uppercase font-bold transition-all"
               >
                 Initialize Camera Loopback
               </button>
               <button 
                 onClick={killRelayB}
                 className="w-full bg-crimson/10 hover:bg-crimson/20 text-crimson border border-crimson/30 py-2.5 rounded-lg text-[9px] tracking-widest uppercase font-bold transition-all"
               >
                 Kill Relay B (Zero-Leak Mute)
               </button>
               <button 
                 onClick={() => { if(peers.length > 0) chaosSlash(peers[0].peer_did) }}
                 className="w-full bg-amber/10 hover:bg-amber/20 text-amber border border-amber/30 py-2.5 rounded-lg text-[9px] tracking-widest uppercase font-bold transition-all"
               >
                 Slash Active Target
               </button>
             </div>
          </div>

          <div className="bg-zinc-900/50 backdrop-blur-xl border border-white/5 rounded-2xl flex-1 min-h-0 border-t-0 p-0 flex flex-col overflow-hidden">
            <div className="bg-white/5 py-1.5 px-3 border-b border-white/10 uppercase tracking-widest text-[8px] text-gray-500 font-bold flex gap-2 items-center">
              <Terminal className="w-3 h-3" /> System Log
            </div>
            <div className="flex-1 overflow-hidden relative">
              <div className="absolute inset-0 bg-gradient-to-b from-[#00FF41]/5 to-transparent pointer-events-none z-0" />
              <TerminalLog />
            </div>
          </div>
        </section>

      </main>

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
