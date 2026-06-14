import React, { useMemo } from "react";
import type { TelemetrySnapshot } from "../types/telemetry";
import { TELEMETRY_SAMPLE_INTERVAL_S } from "../types/telemetry";

interface FlatlineChartProps {
  history: TelemetrySnapshot[];
  latest: TelemetrySnapshot | null;
}

const HEIGHT = 100;
const WIDTH = 300;
const HISTORY_CAP = 120;

export const FlatlineChart: React.FC<FlatlineChartProps> = ({ history, latest }) => {
  const skewSeries = useMemo(() => {
    const pts = history.slice(-HISTORY_CAP);
    if (pts.length === 0 && latest) {
      return [latest.clock_skew_us];
    }
    return pts.map((s) => s.clock_skew_us);
  }, [history, latest]);

  const ySpan = useMemo(() => {
    if (skewSeries.length === 0) return 10;
    const peak = Math.max(...skewSeries.map((v) => Math.abs(v)), 1);
    return Math.max(10, peak * 1.25);
  }, [skewSeries]);

  const scaleY = (val: number) => HEIGHT / 2 - (val / ySpan) * (HEIGHT / 2 - 4);
  const scaleX = (idx: number) =>
    skewSeries.length <= 1 ? 0 : (idx / (skewSeries.length - 1)) * WIDTH;

  const path = skewSeries
    .map((val, i) => `${i === 0 ? "M" : "L"}${scaleX(i)},${scaleY(val)}`)
    .join(" ");

  const elapsedS =
    skewSeries.length > 0
      ? ((skewSeries.length - 1) * TELEMETRY_SAMPLE_INTERVAL_S).toFixed(2)
      : "0.00";

  return (
    <div className="relative w-full h-full flex flex-col">
      <h3 className="text-[10px] uppercase font-bold text-gray-500 mb-1 z-10">
        Layer I: Core 0 Clock-Skew Flatline
      </h3>
      <div className="flex-1 min-h-0 relative">
        <div className="absolute left-0 top-0 bottom-0 flex flex-col justify-between text-[8px] text-gray-600 font-mono z-10 py-1">
          <span>+{ySpan.toFixed(0)}µs</span>
          <span>0µs</span>
          <span>-{ySpan.toFixed(0)}µs</span>
        </div>

        <div className="absolute inset-0 border-b border-l border-zinc-800/50 pl-8">
          <div className="absolute w-full h-[1px] bg-cyber/20 top-1/2" />
        </div>

        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="absolute inset-0 w-full h-full overflow-visible pl-8"
        >
          <defs>
            <filter id="glow-cyber">
              <feGaussianBlur stdDeviation="2" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {path && (
            <path
              d={path}
              fill="none"
              stroke="var(--color-cyber)"
              strokeWidth="1.5"
              filter="url(#glow-cyber)"
            />
          )}
        </svg>
      </div>

      <div className="flex gap-4 mt-2 text-[10px] font-mono z-10 justify-between">
        <span className="text-gray-500">
          Δt = {TELEMETRY_SAMPLE_INTERVAL_S}s · window {elapsedS}s
        </span>
        <span className="text-cyber">
          skew: {latest?.clock_skew_us ?? 0}µs · seq {latest?.seq ?? 0}
        </span>
      </div>
    </div>
  );
};
