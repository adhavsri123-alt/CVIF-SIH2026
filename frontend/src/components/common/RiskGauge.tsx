import React from 'react';

interface RiskGaugeProps {
  score: number; // 0.0 to 1.0
  size?: number;
  label?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 140,
  label = 'Composite Risk',
}) => {
  const clamped = Math.max(0, Math.min(1, score));
  const percentage = Math.round(clamped * 100);
  const radius = (size - 24) / 2;
  const circumference = Math.PI * radius; // Half circle
  const strokeDashoffset = circumference - clamped * circumference;

  let strokeColor = '#10b981'; // Accept green
  if (clamped > 0.7) {
    strokeColor = '#ef4444'; // Quarantine red
  } else if (clamped > 0.3) {
    strokeColor = '#f59e0b'; // Review amber
  }

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`}>
        <defs>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="50%" stopColor="#f59e0b" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        {/* Track */}
        <path
          d={`M 12,${size * 0.6} A ${radius},${radius} 0 0,1 ${size - 12},${size * 0.6}`}
          fill="none"
          stroke="#1f2937"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Active Arc */}
        <path
          d={`M 12,${size * 0.6} A ${radius},${radius} 0 0,1 ${size - 12},${size * 0.6}`}
          fill="none"
          stroke={strokeColor}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text
          x={size / 2}
          y={size * 0.55}
          textAnchor="middle"
          fill="#f9fafb"
          fontSize="24"
          fontWeight="bold"
          fontFamily="inherit"
        >
          {percentage}%
        </text>
      </svg>
      {label && (
        <span style={{ fontSize: '0.8rem', color: '#9ca3af', marginTop: '2px', fontWeight: 500 }}>
          {label}
        </span>
      )}
    </div>
  );
};
