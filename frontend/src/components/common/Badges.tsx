import React from 'react';
import { Disposition, SeverityLevel } from '../../types/api';
import { ShieldCheck, AlertTriangle, ShieldAlert, Info } from 'lucide-react';

export const DispositionBadge: React.FC<{ disposition: Disposition }> = ({ disposition }) => {
  switch (disposition) {
    case 'ACCEPT':
      return (
        <span className="badge badge-accept">
          <ShieldCheck size={14} /> ACCEPT
        </span>
      );
    case 'REVIEW':
      return (
        <span className="badge badge-review">
          <AlertTriangle size={14} /> REVIEW
        </span>
      );
    case 'QUARANTINE':
      return (
        <span className="badge badge-quarantine">
          <ShieldAlert size={14} /> QUARANTINE
        </span>
      );
    default:
      return <span className="badge badge-info">{disposition}</span>;
  }
};

export const SeverityBadge: React.FC<{ severity: SeverityLevel }> = ({ severity }) => {
  switch (severity) {
    case 'CRITICAL':
      return (
        <span className="badge badge-critical">
          <ShieldAlert size={12} /> CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span className="badge badge-high">
          <AlertTriangle size={12} /> HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span className="badge badge-medium">
          <AlertTriangle size={12} /> MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span className="badge badge-low">
          <Info size={12} /> LOW
        </span>
      );
    case 'INFORMATIONAL':
      return (
        <span className="badge badge-info">
          <Info size={12} /> INFO
        </span>
      );
    default:
      return <span className="badge badge-info">{severity}</span>;
  }
};
