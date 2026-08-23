import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps {
  children: ReactNode;
  variant?: ButtonVariant;
  size?: ButtonSize;
  to?: string;
  href?: string;
  onClick?: () => void;
  className?: string;
  id?: string;
  type?: 'button' | 'submit' | 'reset';
  disabled?: boolean;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-brand-cyan text-brand-bg font-semibold hover:bg-cyan-300 shadow-btn-cyan hover:shadow-btn-cyan transition-all duration-200',
  secondary:
    'bg-brand-blue text-white font-semibold hover:bg-blue-500 shadow-btn-blue hover:shadow-btn-blue transition-all duration-200',
  outline:
    'border border-brand-cyan text-brand-cyan hover:bg-brand-cyan hover:text-brand-bg font-semibold transition-all duration-200',
  ghost:
    'text-brand-subtle hover:text-brand-text font-medium transition-colors duration-200',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-4 py-1.5 text-sm rounded-md',
  md: 'px-5 py-2.5 text-sm rounded-lg',
  lg: 'px-7 py-3 text-base rounded-lg',
};

export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  to,
  href,
  onClick,
  className = '',
  id,
  type = 'button',
  disabled = false,
}: ButtonProps) {
  const classes = `inline-flex items-center justify-center gap-2 ${variantClasses[variant]} ${sizeClasses[size]} ${className}`;

  if (to) {
    return (
      <Link to={to} id={id} className={classes}>
        {children}
      </Link>
    );
  }

  if (href) {
    return (
      <a href={href} id={id} className={classes} target="_blank" rel="noopener noreferrer">
        {children}
      </a>
    );
  }

  return (
    <button id={id} type={type} onClick={onClick} disabled={disabled} className={classes}>
      {children}
    </button>
  );
}
