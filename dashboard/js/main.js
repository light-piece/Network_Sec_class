/* Wiring: picks the service, renders on every state change, routes clicks. */
(function (TCC) {
  'use strict';

  var appEl = document.getElementById('app');
  var statusEl = document.getElementById('demo-status');
  var speedEl = document.getElementById('speed');

  var workflow = new TCC.IncidentWorkflow(function (scenario, speed) {
    return TCC.config.USE_MOCK
      ? new TCC.MockResponseService(scenario, speed)
      : new TCC.ApiResponseService(TCC.config.API_BASE);
  });

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

  var actions = {
    startA: function () { workflow.start('A'); },
    startB: function () { workflow.start('B'); },
    reset: function () { workflow.reset(); },
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
})(window.TCC);
