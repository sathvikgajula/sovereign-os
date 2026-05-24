import React, { useEffect, useState } from 'react';

interface FlatlineChartProps {
    relayA: number;
    relayB: number;
    active: boolean;
}

export const FlatlineChart: React.FC<FlatlineChartProps> = ({ relayA, relayB, active }) => {
    // Keep a rolling history of the last 60 data points (assuming update every 100ms = 6 seconds)
    const [history, setHistory] = useState<{ a: number, b: number }[]>(Array(60).fill({ a: 0, b: 0 }));

    useEffect(() => {
        if (!active) {
            setHistory(prev => [...prev.slice(1), { a: 0, b: 0 }]);
            return;
        }
        setHistory(prev => [...prev.slice(1), { a: relayA, b: relayB }]);
    }, [relayA, relayB, active]);

    const HEIGHT = 100;
    const WIDTH = 300;
    const Y_MAX = 1500;

    const scaleY = (val: number) => HEIGHT - (val / Y_MAX) * HEIGHT;
    const scaleX = (idx: number) => (idx / 59) * WIDTH;

    const leakingA = active && relayA !== 0 && relayA !== 1200 && relayA !== 512;
    const leakingB = active && relayB !== 0 && relayB !== 1200 && relayB !== 512;
    const isLeaking = leakingA || leakingB;

    const pathA = history.map((pt, i) => `${i === 0 ? 'M' : 'L'}${scaleX(i)},${scaleY(pt.a)}`).join(' ');
    const pathB = history.map((pt, i) => `${i === 0 ? 'M' : 'L'}${scaleX(i)},${scaleY(pt.b)}`).join(' ');

    return (
        <div className={`relative w-full h-full flex flex-col ${isLeaking ? 'animate-flicker border-crimson' : ''}`}>
            <h3 className="text-[10px] uppercase font-bold text-gray-500 mb-1 z-10">Physics Layer: Traffic CBR</h3>
            <div className="flex-1 min-h-0 relative">
                {/* Y-axis labels */}
                <div className="absolute left-0 top-0 bottom-0 flex flex-col justify-between text-[8px] text-gray-600 font-mono z-10 py-1">
                    <span>1500B</span>
                    <span>1200B</span>
                    <span>512B</span>
                    <span>0B</span>
                </div>
                
                {/* Chart Grid Lines */}
                <div className="absolute inset-0 border-b border-l border-zinc-800/50">
                    <div className="absolute w-full h-[1px] bg-cyber/10 top-[20%]" /> {/* 1200B mark approx */}
                    <div className="absolute w-full h-[1px] bg-gray-500/20 top-[65.8%]" /> {/* 512B mark approx */}
                </div>

                <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="absolute inset-0 w-full h-full preserve-3d overflow-visible pl-8">
                    {/* Glow Filter */}
                    <defs>
                        <filter id="glow-cyber"><feGaussianBlur stdDeviation="3" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                        <filter id="glow-crimson"><feGaussianBlur stdDeviation="4" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                    </defs>

                    <path 
                        d={pathA} 
                        fill="none" 
                        stroke={isLeaking ? "var(--color-crimson)" : "var(--color-cyber)"} 
                        strokeWidth="2"
                        filter={isLeaking ? "url(#glow-crimson)" : "url(#glow-cyber)"}
                        className="transition-colors duration-100"
                    />
                    <path 
                        d={pathB} 
                        fill="none" 
                        stroke={isLeaking ? "var(--color-crimson)" : "var(--color-amber)"} 
                        strokeWidth="1.5"
                        strokeDasharray="4 2"
                        className="transition-colors duration-100 opacity-80"
                    />
                </svg>

                {isLeaking && (
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                        <span className="bg-crimson/20 text-crimson border border-crimson px-2 py-1 rounded text-xs font-bold uppercase animate-pulse backdrop-blur-sm">
                            METADATA LEAK DETECTED
                        </span>
                    </div>
                )}
            </div>
            
            <div className="flex gap-4 mt-2 text-[10px] font-mono z-10 justify-end">
                <span className="text-cyber flex items-center gap-1"><div className="w-2 h-2 bg-cyber rounded-full"/> Relay A: {relayA}B</span>
                <span className="text-amber flex items-center gap-1"><div className="w-2 h-2 bg-amber rounded-full"/> Relay B: {relayB}B</span>
            </div>
        </div>
    );
};
