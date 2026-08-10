/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:       '#050505',
          surface:  '#0D0D0D',
          surface2: '#131313',
          panel:    '#161616',
          border:   'rgba(255,255,255,0.08)',
          cyan:     '#00DCE5',
          'cyan-bright': '#00F5FF',
          'cyan-dim':    '#00A8B0',
          purple:   '#B600F8',
          'purple-dim':  '#7A00A8',
          text:     '#E5E2E1',
          muted:    '#849495',
          dim:      '#3A4949',
        },
      },
      fontFamily: {
        display: ['Geist', 'sans-serif'],
        mono:    ['JetBrains Mono', 'monospace'],
        body:    ['Geist', 'sans-serif'],
      },
      animation: {
        'spin-slow':    'spin 8s linear infinite',
        'pulse-glow':   'pulseGlow 2s ease-in-out infinite',
        'scan-h':       'scanH 3s linear infinite',
        'scan-v':       'scanV 4s linear infinite',
        'float':        'float 6s ease-in-out infinite',
        'float-slow':   'float 10s ease-in-out infinite',
        'marquee':      'marquee 30s linear infinite',
        'marquee-rev':  'marqueeRev 30s linear infinite',
        'glitch':       'glitch 0.4s cubic-bezier(0.25,0.46,0.45,0.94) both',
        'border-trace': 'borderTrace 2s linear infinite',
        'radar':        'radar 3s linear infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%,100%': { opacity: '1', boxShadow: '0 0 20px rgba(0,220,229,0.4)' },
          '50%':     { opacity: '0.7', boxShadow: '0 0 40px rgba(0,220,229,0.8), 0 0 80px rgba(0,220,229,0.3)' },
        },
        scanH: {
          '0%':   { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100vw)' },
        },
        scanV: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        float: {
          '0%,100%': { transform: 'translateY(0px)' },
          '50%':     { transform: 'translateY(-20px)' },
        },
        marquee: {
          '0%':   { transform: 'translateX(0%)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        marqueeRev: {
          '0%':   { transform: 'translateX(-50%)' },
          '100%': { transform: 'translateX(0%)' },
        },
        glitch: {
          '0%':   { transform: 'translate(0)', opacity: '1' },
          '20%':  { transform: 'translate(-3px, 3px)', opacity: '0.8' },
          '40%':  { transform: 'translate(-3px, -3px)', opacity: '0.9' },
          '60%':  { transform: 'translate(3px, 3px)', opacity: '0.8' },
          '80%':  { transform: 'translate(3px, -3px)', opacity: '0.9' },
          '100%': { transform: 'translate(0)', opacity: '1' },
        },
        borderTrace: {
          '0%':   { backgroundPosition: '0% 0%' },
          '100%': { backgroundPosition: '400% 0%' },
        },
        radar: {
          '0%':   { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
      boxShadow: {
        'neon-cyan':   '0 0 20px rgba(0,220,229,0.5), 0 0 40px rgba(0,220,229,0.3)',
        'neon-purple': '0 0 20px rgba(182,0,248,0.5), 0 0 40px rgba(182,0,248,0.3)',
        'neon-sm':     '0 0 10px rgba(0,220,229,0.4)',
        'glass':       '0 8px 32px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05)',
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
