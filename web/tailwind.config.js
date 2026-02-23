/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        proxmox: {
          orange: 'var(--color-primary, #E57000)',
          dark: 'var(--color-dark, #0F1419)',
          darker: 'var(--color-darker, #080B0E)',
          card: 'var(--color-card, #161B22)',
          border: 'var(--color-border, #30363D)',
          hover: 'var(--color-hover, #1C2128)',
        },
        theme: {
          primary: 'var(--color-primary, #E57000)',
          success: 'var(--color-success, #3FB950)',
          warning: 'var(--color-warning, #D29922)',
          error: 'var(--color-error, #F85149)',
          info: 'var(--color-info, #58A6FF)',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        gradient: 'gradient 8s ease infinite',
        'slide-up': 'slideUp 0.5s ease-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
        'scale-in': 'scaleIn 0.3s ease-out',
        glow: 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        gradient: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%': { opacity: '0', transform: 'translateX(-10px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 20px var(--color-primary, rgba(229, 112, 0, 0.3))' },
          '100%': { boxShadow: '0 0 40px var(--color-primary, rgba(229, 112, 0, 0.6))' },
        },
      },
    },
  },
  plugins: [],
};
