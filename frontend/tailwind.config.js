/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          bg:        '#080c14',
          surface:   '#0d1117',
          card:      '#111827',
          border:    '#1e2d3d',
          cyan:      '#22d3ee',
          'cyan-dim': '#0e7490',
          blue:      '#3b82f6',
          'blue-dim': '#1d4ed8',
          muted:     '#6b7280',
          text:      '#e2e8f0',
          subtle:    '#94a3b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      keyframes: {
        fadeInUp: {
          '0%':   { opacity: '0', transform: 'translateY(24px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        pulse: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.4' },
        },
      },
      animation: {
        'fade-in-up':    'fadeInUp 0.6s ease-out forwards',
        'fade-in':       'fadeIn 0.5s ease-out forwards',
        'pulse-slow':    'pulse 3s ease-in-out infinite',
      },
      backgroundImage: {
        'grid-pattern': 'linear-gradient(rgba(34,211,238,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.03) 1px, transparent 1px)',
        'hero-glow':    'radial-gradient(ellipse 80% 60% at 50% -10%, rgba(34,211,238,0.12) 0%, transparent 70%)',
        'cta-glow':     'radial-gradient(ellipse 70% 80% at 50% 50%, rgba(59,130,246,0.08) 0%, transparent 70%)',
      },
      backgroundSize: {
        'grid': '48px 48px',
      },
      boxShadow: {
        'card':    '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px rgba(30,45,61,0.8)',
        'card-hover': '0 4px 20px rgba(0,0,0,0.5), 0 0 0 1px rgba(34,211,238,0.2)',
        'btn-cyan': '0 0 20px rgba(34,211,238,0.25)',
        'btn-blue': '0 0 20px rgba(59,130,246,0.25)',
      },
    },
  },
  plugins: [],
}
