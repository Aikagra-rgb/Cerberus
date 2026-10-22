import React from "react";
import { AlertRecord, SeverityLevel, severityFor, SEVERITY_COLOR_HEX } from "../types";

// ── 1. Threat Distribution Donut Chart ──────────────────────────────────────
interface DonutChartProps {
  alerts: AlertRecord[];
  onSelectType?: (type: string) => void;
}

const PALETTE = [
  "#06b6d4",
  "#8b5cf6",
  "#ff1f5a",
  "#ff9f0a",
  "#10b981",
  "#ec4899",
  "#3b82f6",
  "#eab308",
];

export const ThreatDonutChart: React.FC<DonutChartProps> = ({ alerts, onSelectType }) => {
  const counts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.Type] = (acc[a.Type] || 0) + 1;
    return acc;
  }, {});

  const entries = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  const total = alerts.length;

  if (total === 0) {
    return (
      <div className="empty-chart">
        <span>No alert distribution data in current filter</span>
      </div>
    );
  }

  const radius = 68;
  const strokeWidth = 22;
  const circumference = 2 * Math.PI * radius;
  let cumulativeFraction = 0;

  return (
    <div className="donut-layout">
      <div className="donut-svg-wrap">
        <svg viewBox="0 0 180 180" className="donut-svg">
          <circle
            cx="90"
            cy="90"
            r={radius}
            fill="transparent"
            stroke="rgba(148, 163, 184, 0.08)"
            strokeWidth={strokeWidth}
          />
          {entries.map(([type, count], idx) => {
            const fraction = count / total;
            const dashArray = `${Math.max(1, fraction * circumference - 2)} ${circumference}`;
            const dashOffset = -cumulativeFraction * circumference;
            cumulativeFraction += fraction;
            const color = PALETTE[idx % PALETTE.length];
            return (
              <circle
                key={type}
                cx="90"
                cy="90"
                r={radius}
                fill="transparent"
                stroke={color}
                strokeWidth={strokeWidth}
                strokeDasharray={dashArray}
                strokeDashoffset={dashOffset}
                transform="rotate(-90 90 90)"
                style={{ cursor: onSelectType ? "pointer" : "default", transition: "all 0.5s ease" }}
                onClick={() => onSelectType?.(type)}
              >
                <title>{`${type}: ${count} (${((count / total) * 100).toFixed(1)}%)`}</title>
              </circle>
            );
          })}
          <text x="90" y="84" textAnchor="middle" className="donut-center-num">
            {total}
          </text>
          <text x="90" y="104" textAnchor="middle" className="donut-center-label">
            ALERTS
          </text>
        </svg>
      </div>

      <div className="donut-legend">
        {entries.map(([type, count], idx) => {
          const pct = ((count / total) * 100).toFixed(1);
          const color = PALETTE[idx % PALETTE.length];
          return (
            <button
              key={type}
              type="button"
              className="legend-row"
              onClick={() => onSelectType?.(type)}
              title={`Filter by ${type}`}
            >
              <span className="legend-dot" style={{ background: color }} />
              <span className="legend-name">{type}</span>
              <span className="legend-val">
                {count} <small>({pct}%)</small>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

// ── 2. Top Attacker IPs Horizontal Bar Chart ────────────────────────────────
interface TopAttackersProps {
  alerts: AlertRecord[];
  onSelectIP?: (ip: string) => void;
}

export const TopAttackersChart: React.FC<TopAttackersProps> = ({ alerts, onSelectIP }) => {
  const ipCounts = alerts.reduce<Record<string, { count: number; maxSeverity: SeverityLevel }>>(
    (acc, a) => {
      const ip = a["Source IP"] || "Unknown";
      const sev = severityFor(a.Type);
      const sevRank: Record<SeverityLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      if (!acc[ip]) {
        acc[ip] = { count: 0, maxSeverity: sev };
      }
      acc[ip].count += 1;
      if (sevRank[sev] > sevRank[acc[ip].maxSeverity]) {
        acc[ip].maxSeverity = sev;
      }
      return acc;
    },
    {}
  );

  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  if (topIPs.length === 0) {
    return (
      <div className="empty-chart">
        <span>No attacker telemetry recorded</span>
      </div>
    );
  }

  const maxCount = Math.max(1, ...topIPs.map(([, d]) => d.count));

  return (
    <div className="attacker-bars">
      {topIPs.map(([ip, data]) => {
        const widthPct = Math.max(6, Math.round((data.count / maxCount) * 100));
        const color = SEVERITY_COLOR_HEX[data.maxSeverity];
        return (
          <div
            key={ip}
            className="attacker-bar-row"
            onClick={() => onSelectIP?.(ip)}
            style={{ cursor: onSelectIP ? "pointer" : "default" }}
            title={`Click to filter alerts from ${ip}`}
          >
            <div className="attacker-bar-meta">
              <span className="mono attacker-ip">{ip}</span>
              <span className="attacker-count">
                <strong>{data.count}</strong> events
              </span>
            </div>
            <div className="bar-track">
              <span
                className="bar-fill"
                style={{
                  width: `${widthPct}%`,
                  background: `linear-gradient(90deg, #06b6d4, ${color})`,
                  boxShadow: `0 0 10px ${color}66`,
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ── 3. Incident Activity Timeline Area Chart ────────────────────────────────
interface TimelineChartProps {
  alerts: AlertRecord[];
}

export const AlertTimelineChart: React.FC<TimelineChartProps> = ({ alerts }) => {
  if (alerts.length === 0) {
    return (
      <div className="empty-chart">
        <span>Awaiting timestamped telemetry to plot timeline</span>
      </div>
    );
  }

  // Group into 12 buckets across the alert sequence or by hour/minute
  const bucketMap = new Map<string, { total: number; critical: number }>();
  const reversed = [...alerts].slice(0, 120).reverse();

  for (const a of reversed) {
    const raw = a.Timestamp || "";
    const timePart = raw.includes(" ") ? raw.split(" ")[1]?.slice(0, 5) : raw.slice(11, 16);
    const label = timePart || "Now";
    const entry = bucketMap.get(label) || { total: 0, critical: 0 };
    entry.total += 1;
    if (severityFor(a.Type) === "CRITICAL") {
      entry.critical += 1;
    }
    bucketMap.set(label, entry);
  }

  const buckets = Array.from(bucketMap.entries()).slice(-12);
  const maxVal = Math.max(1, ...buckets.map(([, v]) => v.total));

  const width = 560;
  const height = 150;
  const padX = 28;
  const padY = 18;
  const plotW = width - padX * 2;
  const plotH = height - padY * 2;

  const points = buckets.map(([label, val], idx) => {
    const x =
      buckets.length === 1
        ? width / 2
        : padX + (idx / (buckets.length - 1)) * plotW;
    const y = padY + plotH - (val.total / maxVal) * plotH;
    const critY = padY + plotH - (val.critical / maxVal) * plotH;
    return { x, y, critY, label, ...val };
  });

  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(" ");

  const areaPath =
    points.length > 0
      ? `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${height - padY} L ${points[0].x.toFixed(1)} ${height - padY} Z`
      : "";

  return (
    <div className="timeline-chart-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} className="timeline-svg">
        <defs>
          <linearGradient id="cyberAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.42" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Horizontal reference lines */}
        {[0, 0.5, 1].map((step) => {
          const y = padY + step * plotH;
          return (
            <line
              key={step}
              x1={padX}
              x2={width - padX}
              y1={y}
              y2={y}
              stroke="rgba(148, 163, 184, 0.1)"
              strokeDasharray="3 3"
            />
          );
        })}

        {areaPath && <path d={areaPath} fill="url(#cyberAreaGrad)" />}
        {linePath && (
          <path
            d={linePath}
            fill="none"
            stroke="#06b6d4"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        )}

        {points.map((p, idx) => (
          <g key={`${p.label}-${idx}`}>
            <circle
              cx={p.x}
              cy={p.y}
              r={4}
              fill={p.critical > 0 ? "#ff1f5a" : "#06b6d4"}
              stroke="#04070f"
              strokeWidth="1.5"
            >
              <title>{`${p.label} — ${p.total} alerts (${p.critical} critical)`}</title>
            </circle>
            {(idx === 0 || idx === points.length - 1 || idx % 2 === 0) && (
              <text
                x={p.x}
                y={height - 3}
                textAnchor="middle"
                className="timeline-axis-label"
              >
                {p.label}
              </text>
            )}
          </g>
        ))}
      </svg>
    </div>
  );
};
