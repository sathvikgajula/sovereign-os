import React, { useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';

export const TerminalLog: React.FC = () => {
    const [logs, setLogs] = useState<string[]>([]);
    const endRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        // Initial Startup Log
        setLogs(prev => [...prev, "> System initialized", "> Awaiting telemetry hooks..."]);

        // Resolve Real System Logs/Errors
        const unlistenLog = listen<string>("system-log", (event) => {
            setLogs(prev => [...prev.slice(-49), "> " + event.payload]);
        });

        const unlistenErr = listen<string>("system-error", (event) => {
            setLogs(prev => [...prev.slice(-49), "!! ERR: " + event.payload]);
        });

        return () => {
            unlistenLog.then(u => u());
            unlistenErr.then(u => u());
        };
    }, []);

    useEffect(() => {
        endRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    return (
        <div className="w-full h-full flex flex-col font-mono text-[10px] text-[#00FF41] overflow-hidden p-2">
            <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col gap-0.5">
                {logs.map((log, i) => (
                    <div key={i} className="opacity-80 hover:opacity-100">{log}</div>
                ))}
                <div ref={endRef} />
            </div>
        </div>
    );
};
