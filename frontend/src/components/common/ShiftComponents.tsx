import React from 'react';
import { DimensionShiftInfo } from '../../types/api';
import { CheckCircle, AlertTriangle } from 'lucide-react';

export const AttributionBar: React.FC<{
  naturalDrift: number;
  suspiciousManipulation: number;
}> = ({ naturalDrift, suspiciousManipulation }) => {
  const natPct = Math.round(naturalDrift * 100);
  const suspPct = Math.round(suspiciousManipulation * 100);

  return (
    <div style={{ marginBottom: '16px' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: '0.85rem',
          marginBottom: '6px',
        }}
      >
        <span style={{ color: '#60a5fa', fontWeight: 500 }}>
          Natural Drift Likelihood: {natPct}%
        </span>
        <span style={{ color: '#f87171', fontWeight: 500 }}>
          Suspicious Manipulation Likelihood: {suspPct}%
        </span>
      </div>

      <div
        style={{
          height: '14px',
          width: '100%',
          backgroundColor: '#1f2937',
          borderRadius: '9999px',
          display: 'flex',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${natPct}%`,
            backgroundColor: '#3b82f6',
            transition: 'width 0.4s ease',
          }}
        />
        <div
          style={{
            width: `${suspPct}%`,
            backgroundColor: '#ef4444',
            transition: 'width 0.4s ease',
          }}
        />
      </div>
    </div>
  );
};

export const ShiftMatrix: React.FC<{
  dimensions: Record<string, DimensionShiftInfo>;
}> = ({ dimensions }) => {
  const dimKeys = Object.keys(dimensions);

  if (dimKeys.length === 0) {
    return <p style={{ color: 'var(--text-muted)' }}>No dimension data available.</p>;
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Dimension</th>
            <th>Status</th>
            <th>Distance / Statistic</th>
            <th>Threshold</th>
            <th>p-value</th>
          </tr>
        </thead>
        <tbody>
          {dimKeys.map((key) => {
            const dim = dimensions[key];
            return (
              <tr key={key}>
                <td style={{ fontWeight: 600 }}>{dim.dimension_name || key}</td>
                <td>
                  {dim.shift_detected ? (
                    <span className="badge badge-quarantine">
                      <AlertTriangle size={12} /> SHIFT DETECTED
                    </span>
                  ) : (
                    <span className="badge badge-accept">
                      <CheckCircle size={12} /> NOMINAL
                    </span>
                  )}
                </td>
                <td className="font-mono">
                  {typeof dim.statistic_value === 'number'
                    ? dim.statistic_value.toFixed(4)
                    : 'N/A'}
                </td>
                <td className="font-mono">
                  {typeof dim.threshold === 'number' ? dim.threshold.toFixed(4) : 'N/A'}
                </td>
                <td className="font-mono">
                  {typeof dim.p_value === 'number' ? dim.p_value.toFixed(4) : 'N/A'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
