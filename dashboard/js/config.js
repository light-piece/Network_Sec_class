/* App configuration.
   USE_MOCK = 'auto' → ask the backend (GET API_BASE/status) at startup: if it answers,
                       use the real backend; otherwise run the in-browser simulation.
   USE_MOCK = true   → everything is simulated in the browser (offline demo).
   USE_MOCK = false  → always call the FastAPI backend at API_BASE. */
window.TCC = window.TCC || {};
TCC.config = {
  USE_MOCK: 'auto',
  API_BASE: '/api'
};
