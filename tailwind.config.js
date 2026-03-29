/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./public/**/*.html'],
  theme: {
    extend: {},
  },
  plugins: [],
  // Classes used only inside JS template strings (infra load meter)
  safelist: [
    'supports-[backdrop-filter]:bg-[#08080c]/85',
    'from-emerald-400/95',
    'to-emerald-500',
    'from-cyan-300/90',
    'to-blue-500',
    'from-amber-400',
    'to-orange-500',
    'shadow-[0_0_10px_rgba(52,211,153,0.35)]',
    'shadow-[0_0_10px_rgba(185,253,236,0.25)]',
    'shadow-[0_0_10px_rgba(251,146,60,0.35)]',
    'transition-[width]',
    'ring-inset',
    'rounded-[2px]',
    'rounded-[1px]',
    'tracking-[0.2em]',
  ],
};
