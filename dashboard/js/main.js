/* Wiring: decides mock or real mode, picks the service, renders on every state change, routes clicks. */
(function (TCC) {
  'use strict';

  var appEl = document.getElementById('app');
  var statusEl = document.getElementById('demo-status');
  var speedEl = document.getElementById('speed');

  /* USE_MOCK: true / false force a mode; 'auto' asks GET {API_BASE}/status and uses the
     real backend only if it answers. Resolves to { mock: bool, status: object|null }. */
  function decideMode() {
    var cfg = TCC.config, api = new TCC.ApiResponseService(cfg.API_BASE);
    if (cfg.USE_MOCK === true) return Promise.resolve({ mock: true, status: null });
    var ask = Promise.race([
      api.getStatus(),
      new Promise(function (_, reject) { setTimeout(function () { reject(new Error('timeout')); }, 3000); })
    ]);
    if (cfg.USE_MOCK === false) {
      return ask.then(function (st) { return { mock: false, status: st }; },
        function () { return { mock: false, status: null }; });
    }
    return ask.then(function (st) {
      return st && st.backend ? { mock: false, status: st } : { mock: true, status: null };
    }, function () { return { mock: true, status: null }; });
  }

  /* Real mode: live-lab controls instead of the simulation controls (mock mode is unchanged). */
  function setupRealBar(status) {
    document.getElementById('demo-label').textContent = 'LIVE LAB';
    document.querySelectorAll('[data-mode="mock"]').forEach(function (el) { el.hidden = true; });
    document.getElementById('speed-control').hidden = true;
    document.querySelector('[data-action="runAttack"]').hidden = false;
    document.querySelector('[data-action="reset"]').textContent = 'Reset lab';
    var ai = document.getElementById('demo-ai');
    ai.textContent = 'AI: ' + ((status && status.aiModel) || 'unknown');
    if (status && status.aiReachable === false) ai.textContent += ' (unreachable)';
    ai.hidden = false;
    document.getElementById('footnote').hidden = true;
    document.querySelector('.demo-actions').setAttribute('aria-label', 'Lab controls');
  }

  function wire(mode) {
    var mock = mode.mock;
    TCC.mode = mock ? 'mock' : 'real';
    var api = mock ? null : new TCC.ApiResponseService(TCC.config.API_BASE);
    if (!mock) setupRealBar(mode.status);

    var workflow = new TCC.IncidentWorkflow(function (scenario, speed) {
      return mock ? new TCC.MockResponseService(scenario, speed) : api;
    }, { realTime: !mock });

    function render(state) {
      // Keep keyboard focus on the same control across re-renders.
      var focusedKey = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.key : null;
      appEl.innerHTML = TCC.renderApp(state);
      statusEl.textContent = TCC.demoStatus(state);
      if (focusedKey) {
        var again = appEl.querySelector('[data-key="' + focusedKey + '"]');
        if (again && !again.disabled) again.focus();
      }
    }

    var busy = false;   // a lab request (attack / reset) is in flight
    function labCall(promise, then) {
      if (busy) return;
      busy = true;
      promise.then(function () { busy = false; then(); }, function (e) {
        busy = false;
        console.error(e);
        workflow.reset();
        workflow.fail(e);
      });
    }

    var actions = {
      startA: function () { if (mock) workflow.start('A'); },
      startB: function () { if (mock) workflow.start('B'); },
      runAttack: function () {
        if (mock) return;
        labCall(api.runAttack(), function () { workflow.start('live'); });
      },
      reset: function () {
        if (mock) return workflow.reset();
        workflow.reset();
        labCall(api.resetLab(), function () { workflow.reset(); });
      },
      approve: function () { workflow.approve(); },
      reject: function () { workflow.reject(); },
      requestAnother: function () { workflow.requestAnother(); },
      sendFeedback: function () { workflow.sendFeedback(); },
      toggleDetails: function () { workflow.toggleDetails(); }
    };

    document.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-action]');
      if (!btn || btn.disabled) return;
      var fn = actions[btn.dataset.action];
      if (fn) fn();
    });
    speedEl.addEventListener('change', function () { workflow.setSpeed(speedEl.value); });

    workflow.setSpeed(speedEl.value);
    workflow.subscribe(render);

    TCC.workflow = workflow; // handy for debugging in the browser console
  }

  decideMode().then(wire);
})(window.TCC);
