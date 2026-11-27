import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string;
  icon?: ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger';
}

export function StatCard({ title, value, icon, variant = 'default' }: StatCardProps) {
  const variantClasses = {
    default: 'border-base-600',
    success: 'border-accent-green/30',
    warning: 'border-accent-yellow/30',
    danger: 'border-accent-red/30',
  };

  const valueClasses = {
    default: 'text-base-100',
    success: 'text-accent-green',
    warning: 'text-accent-yellow',
    danger: 'text-accent-red',
  };

  return (
    <div className={cn('card p-6', variantClasses[variant])}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-base-400 mb-1">{title}</p>
          <p className={cn('text-2xl font-bold font-mono', valueClasses[variant])}>{value}</p>
        </div>
        {icon && <div className="text-accent-blue opacity-70">{icon}</div>}
      </div>
    </div>
  );
}
