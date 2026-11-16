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

## Connecting the real backend (week 2)

1. Build FastAPI endpoints that return the shapes described at the top of `js/mock-service.js`.
2. Adjust the paths in `js/api-service.js` to match your routes.
3. Set `USE_MOCK: false` in `js/config.js`.
4. Allow the dashboard's origin in FastAPI's CORS settings.

The workflow and the UI don't change; only the service does.
