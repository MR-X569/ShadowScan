import React, { useRef, useEffect } from 'react';

interface OtpInputProps {
  length?: number;
  value: string;
  onChange: (otp: string) => void;
  disabled?: boolean;
  error?: boolean;
  idPrefix?: string;
  autoFocus?: boolean;
}

export default function OtpInput({
  length = 6,
  value,
  onChange,
  disabled = false,
  error = false,
  idPrefix = 'otp-input',
  autoFocus = true,
}: OtpInputProps) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Split current value into array of length
  const digits = Array.from({ length }, (_, i) => value[i] || '');

  useEffect(() => {
    if (autoFocus && inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, [autoFocus]);

  const handleChange = (index: number, e: React.ChangeEvent<HTMLInputElement>) => {
    const rawVal = e.target.value;
    // Take only numeric characters
    const numericVal = rawVal.replace(/\D/g, '');

    if (!numericVal) {
      // Empty / deleted
      const newDigits = [...digits];
      newDigits[index] = '';
      onChange(newDigits.join(''));
      return;
    }

    // If pasted or typed multiple digits in a single input
    if (numericVal.length > 1) {
      handlePastedDigits(index, numericVal);
      return;
    }

    // Single digit entered
    const char = numericVal[numericVal.length - 1];
    const newDigits = [...digits];
    newDigits[index] = char;
    const newOtp = newDigits.join('');
    onChange(newOtp);

    // Auto focus next input
    if (index < length - 1 && char) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      if (!digits[index] && index > 0) {
        // Move to previous input and clear it
        e.preventDefault();
        const newDigits = [...digits];
        newDigits[index - 1] = '';
        onChange(newDigits.join(''));
        inputRefs.current[index - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      e.preventDefault();
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < length - 1) {
      e.preventDefault();
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasteData = e.clipboardData.getData('text');
    const numericPaste = pasteData.replace(/\D/g, '');
    if (!numericPaste) return;
    handlePastedDigits(0, numericPaste);
  };

  const handlePastedDigits = (startIndex: number, pastedString: string) => {
    const newDigits = [...digits];
    let writeIdx = startIndex;
    for (let i = 0; i < pastedString.length && writeIdx < length; i++) {
      newDigits[writeIdx] = pastedString[i];
      writeIdx++;
    }
    const combined = newDigits.join('');
    onChange(combined);

    const nextFocusIdx = Math.min(writeIdx, length - 1);
    inputRefs.current[nextFocusIdx]?.focus();
  };

  return (
    <div className="flex items-center justify-center gap-2 sm:gap-3" role="group" aria-label="OTP verification code">
      {Array.from({ length }).map((_, index) => (
        <input
          key={index}
          ref={(el) => {
            inputRefs.current[index] = el;
          }}
          id={`${idPrefix}-${index}`}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={1}
          autoComplete={index === 0 ? 'one-time-code' : 'off'}
          value={digits[index]}
          disabled={disabled}
          onChange={(e) => handleChange(index, e)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={handlePaste}
          onFocus={(e) => e.target.select()}
          aria-label={`Digit ${index + 1} of ${length}`}
          className={[
            'h-12 w-10 sm:h-14 sm:w-12 rounded-xl border text-center font-mono text-xl sm:text-2xl font-bold outline-none transition-all duration-200',
            'bg-brand-surface text-brand-text selection:bg-brand-cyan/20',
            error
              ? 'border-red-500/60 bg-red-500/5 text-red-300 focus:border-red-500 focus:ring-2 focus:ring-red-500/20'
              : digits[index]
              ? 'border-brand-cyan/60 bg-brand-surface shadow-btn-cyan/10 focus:border-brand-cyan focus:ring-2 focus:ring-brand-cyan/30'
              : 'border-brand-border hover:border-brand-cyan/30 focus:border-brand-cyan focus:ring-2 focus:ring-brand-cyan/30',
            disabled ? 'cursor-not-allowed opacity-50' : '',
          ]
            .filter(Boolean)
            .join(' ')}
        />
      ))}
    </div>
  );
}
