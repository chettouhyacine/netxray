/** @type {import('tailwindcss').Config} */
export default {
  content: ['./devtools.html', './panel.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#080b12',
          900: '#0b0f17',
          850: '#111725',
          800: '#161d2d',
          700: '#1f2939',
          600: '#2c384d',
          500: '#3c4a63',
        },
        accent: {
          DEFAULT: '#38e1c6',
          soft: '#7df0dd',
          dim: '#1c8f80',
        },
        phase: {
          blocked: '#64748b',
          dns: '#8b5cf6',
          tcp: '#3b82f6',
          tls: '#14b8a6',
          request: '#f59e0b',
          wait: '#f97316',
          download: '#22c55e',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      keyframes: {
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        pulse_ring: {
          '0%': { opacity: '0.6', transform: 'scale(0.9)' },
          '100%': { opacity: '0', transform: 'scale(1.6)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 160ms ease-out',
      },
    },
  },
  plugins: [],
};
