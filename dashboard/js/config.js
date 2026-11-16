/* App configuration.
   USE_MOCK = true  → everything is simulated in the browser (week 1).
   USE_MOCK = false → the dashboard calls your FastAPI backend at API_BASE (week 2+). */
window.TCC = window.TCC || {};
TCC.config = {
  USE_MOCK: true,
  API_BASE: 'http://localhost:8000/api'
};
