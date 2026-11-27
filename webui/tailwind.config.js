/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Aurora Dark palette — shared with the main NCP web panel.
        // Same token names as before, new values: restyle happens here.
        border: '#1c2436',
        input: '#2a3448',
        ring: '#22d3ee',
        base: {
          50: '#e6ebf5',
          100: '#c6d0e0',
          200: '#9aa8bf',
          300: '#7b8aa5',
          400: '#5d6c85',
          500: '#3b4760',
          600: '#2a3448',
          700: '#1c2436',
          800: '#151b28',
          900: '#10151f',
          950: '#0a0e16',
        },
        surface: {
          DEFAULT: '#10151f',
          0: '#0a0e16',
          1: '#10151f',
          2: '#151b28',
        },
        accent: {
          blue: '#22d3ee',      // primary cyan
          green: '#34d399',
          red: '#fb7185',
          yellow: '#fbbf24',
          orange: '#fb923c',
          mauve: '#818cf8',     // secondary indigo
          teal: '#2dd4bf',
          pink: '#f472b6',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      boxShadow: {
        card: '0 1px 3px rgba(0, 0, 0, 0.45), 0 4px 16px rgba(0, 0, 0, 0.25)',
        glow: '0 0 24px rgba(34, 211, 238, 0.15)',
      },
      backgroundImage: {
        'accent-gradient': 'linear-gradient(135deg, #22d3ee, #818cf8)',
        'aurora':
          'radial-gradient(1000px 500px at 15% -10%, rgba(34,211,238,0.10), transparent 55%),' +
          'radial-gradient(900px 480px at 110% 10%, rgba(129,140,248,0.09), transparent 55%),' +
          'radial-gradient(700px 420px at 50% 120%, rgba(52,211,153,0.05), transparent 60%)',
      },
    },
  },
  plugins: [],
};
