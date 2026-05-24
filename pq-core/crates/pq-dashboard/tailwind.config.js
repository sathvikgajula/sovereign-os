/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber': '#00F0FF',
        'amber': '#FFBF00',
        'crimson': '#FF003C',
        'deep': '#050505',
        'pq-green': '#10b981',
        'pq-gray': '#6b7280',
        'pq-red': '#ef4444',
      },
    },
  },
  plugins: [],
}
