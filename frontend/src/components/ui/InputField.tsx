import { forwardRef } from 'react';
import type { InputHTMLAttributes } from 'react';

interface InputFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  id: string;
  error?: string;
  rightElement?: React.ReactNode;
}

const InputField = forwardRef<HTMLInputElement, InputFieldProps>(
  ({ label, id, error, rightElement, className = '', ...rest }, ref) => {
    return (
      <div className="flex flex-col gap-1.5">
        <label htmlFor={id} className="text-sm font-medium text-brand-subtle">
          {label}
        </label>
        <div className="relative">
          <input
            ref={ref}
            id={id}
            className={[
              'w-full rounded-lg border bg-brand-surface px-3.5 py-2.5 text-sm text-brand-text placeholder:text-brand-muted outline-none transition-all duration-200',
              'focus:border-brand-cyan focus:ring-1 focus:ring-brand-cyan/30',
              error
                ? 'border-red-500/60 focus:border-red-500 focus:ring-red-500/20'
                : 'border-brand-border hover:border-brand-cyan/30',
              rightElement ? 'pr-10' : '',
              className,
            ]
              .filter(Boolean)
              .join(' ')}
            {...rest}
          />
          {rightElement && (
            <div className="absolute inset-y-0 right-0 flex items-center pr-3">
              {rightElement}
            </div>
          )}
        </div>
        {error && (
          <p className="text-xs text-red-400" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  }
);

InputField.displayName = 'InputField';

export default InputField;
