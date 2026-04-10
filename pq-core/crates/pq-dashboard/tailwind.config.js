/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'pq-green': '#10b981',
        'pq-gray': '#6b7280',
        'pq-red': '#ef4444',
      },
    },
  },
  plugins: [],
}
