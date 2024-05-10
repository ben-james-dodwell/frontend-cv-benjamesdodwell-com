/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/index.html"],
  theme: {
    extend: {
      colors: {
        'cv-blue': '#243c5a',
      },
      boxShadow: {
        'right': 'inset -16px 0 16px -16px hsla(0,0%,0%,.2)',
      }
    },
  },
  plugins: [],
}

