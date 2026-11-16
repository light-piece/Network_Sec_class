# Threat Containment Console (dashboard)

Plain HTML, CSS and JavaScript. No build step, no installs.

## Run it

Either double-click `index.html` to open it in your browser, or serve the folder:

```bash
python3 -m http.server 8080 --directory dashboard
```

then open http://localhost:8080.

Use the grey demo bar at the top to run **Simulate A** (fix works) or **Simulate B** (first fix fails), change speed, or **Reset**.

## Files

| File | What it does |
|---|---|
| `index.html` | Page shell: demo bar, app bar, and an empty `<main>` the view fills in |
| `css/styles.css` | All styling. Colors are CSS variables at the top |
| `js/config.js` | `USE_MOCK` switch and the backend URL |
| `js/mock-service.js` | Data contracts, mock data, and `MockResponseService` (simulated backend) |
| `js/api-service.js` | `ApiResponseService`: the same methods, calling FastAPI with `fetch` |
| `js/workflow.js` | The incident state machine (detect → contain → recommend → approve → apply → verify → resolve/revise) |
| `js/view.js` | Turns the current state into HTML. No logic, no network calls |
| `js/main.js` | Connects them: picks the service, re-renders on every change, routes button clicks |

## Mock mode and real mode

`js/config.js` has `USE_MOCK: 'auto'`: at startup the dashboard asks `GET /api/status`.

- **Real mode** (the FastAPI backend serves the dashboard and answers): the bar shows **LIVE LAB**, **Run attack**
  (`POST /api/lab/attack`, then the workflow starts and long-polls for the incident), **Reset lab**
  (`POST /api/lab/reset`) and the AI model in use. Times are real; errors from the API are shown in the incident card
  with a Reset button.
- **Mock mode** (no backend, e.g. `python3 -m http.server` above): the simulated demo with Simulate A/B, speed and Reset.

`USE_MOCK: true` or `false` forces a mode. The API is described in `docs/API_CONTRACT.md`.
