/* Incident workflow controller.
   Owns the state machine and calls the service; knows nothing about HTML.
   Stages: idle → detecting → containing → recommending → awaiting
           → (rejected → recommending) | applying → verifying → resolved
           | failed → (recover) → recommending → awaiting → … */
window.TCC = window.TCC || {};

(function (TCC) {
  'use strict';

  var CANCELLED = { cancelled: true };

  function blankChecks() {
    return { unauthorized_blocked: { status: 'not_tested' }, legitimate_app: { status: 'not_tested' } };
  }
  function blankState() {
    return {
      scenario: null, stage: 'idle', incident: null,
      containment: 'off',   // off | activating | active | lifting | lifted | restoring | retired
      correction: 'none',   // none | drafting | proposed | applying | applied | verified | failed | rolling_back | rolled_back | rejected
      rec: null, recs: [], showDetails: false,
      checks: blankChecks(), checksVersion: null, testedWithoutContainment: false,
      recovery: null, lastFailure: null, timeline: [], times: {},
      error: null           // message shown in the incident card when a service call fails
    };
  }

  class IncidentWorkflow {
    /* createService(scenario, speed) returns a MockResponseService or ApiResponseService.
       options.realTime: use the real clock (real backend) instead of the simulated one. */
    constructor(createService, options) {
      this.createService = createService;
      this.realTime = !!(options && options.realTime);
      this.state = blankState();
      this.listeners = [];
      this.run = 0;
      this.evSeq = 0;
      this.t0 = Date.now();
      this.speed = 'normal';
    }

    subscribe(fn) { this.listeners.push(fn); fn(this.state); }
    setState(patch) {
      var p = typeof patch === 'function' ? patch(this.state) : patch;
      this.state = Object.assign({}, this.state, p);
      var s = this.state;
      this.listeners.forEach(function (fn) { fn(s); });
    }

    /* ---------- helpers ---------- */
    guard(run, p) {
      var self = this;
      return Promise.resolve(p).then(function (v) { if (run !== self.run) throw CANCELLED; return v; });
    }
    now() { return this.realTime ? Date.now() : TCC.SIM_START + (Date.now() - this.t0); }
    mark(key) {
      var t = this.now();
      this.setState(function (s) { var x = Object.assign({}, s.times); x[key] = t; return { times: x }; });
    }
    log(actor, title, detail) {
      var ev = { id: ++this.evSeq, at: this.now(), actor: actor, title: title, detail: detail || '' };
      this.setState(function (s) { return { timeline: [ev].concat(s.timeline) }; });
    }
    safely(fn) {
      var run = this.run, self = this;
      return fn().catch(function (e) {
        if (e === CANCELLED) return;
        console.error(e);
        if (run === self.run) self.fail(e);
      });
    }
    /* Show a failed service call in the incident card (with a Reset button). */
    fail(e) {
      var msg = (e && e.message) || String(e || 'Unknown error');
      this.setState({ error: msg });
      this.log('system', 'Error', msg);
    }

    /* ---------- demo controls ---------- */
    setSpeed(speed) { this.speed = speed; }
    reset() { this.run += 1; this.setState(blankState()); }

    start(scenario) {
      var run = ++this.run, self = this;
      var g = function (p) { return self.guard(run, p); };
      this.svc = this.createService(scenario, this.speed);
      this.t0 = Date.now();
      this.evSeq = 0;
      this.setState(Object.assign(blankState(), { scenario: scenario, stage: 'detecting' }));
      return this.safely(async function () {
        var inc = await g(self.svc.getActiveIncident());
        self.t0 = Date.now();
        var detected = self.realTime ? (inc.detectedAt || Date.now()) : TCC.SIM_START;
        self.setState({ incident: inc, stage: 'containing', containment: 'activating', times: { detected: detected } });
        self.log('system', 'Unauthorized connection detected', inc.source.name + ' → ' + inc.target.name + ' on ' +
          String(inc.connection.protocol).toLowerCase() + '/' + inc.connection.dstPort +
          ', allowed by misconfigured rule #' + inc.policy.ruleId + '.');
        var block = await g(self.svc.activateContainment(inc.id));
        self.setState({ containment: 'active' });
        self.mark('contained');
        self.log('system', 'Temporary block applied', (block && block.ruleId ? 'Rule ' + block.ruleId : 'The temporary block') +
          ' blocks only ' + inc.source.name + ' → database. Application access is unaffected.');
        await self.draft(run, null);
      });
    }

    async draft(run, feedback) {
      var self = this;
      var g = function (p) { return self.guard(run, p); };
      this.setState({ stage: 'recommending', correction: 'drafting', rec: null, showDetails: false });
      var rec = await g(this.svc.requestRecommendation(this.state.incident.id, feedback));
      this.setState(function (s) { return { rec: rec, recs: s.recs.concat([rec]), stage: 'awaiting', correction: 'proposed' }; });
      this.mark('recReady');
      this.log('ai', 'Recommendation version ' + rec.version + ' ready for approval', rec.summary);
    }

    /* ---------- administrator actions ---------- */
    approve() {
      if (this.state.stage !== 'awaiting') return;
      var run = this.run, self = this, rec = this.state.rec, incId = this.state.incident.id;
      var g = function (p) { return self.guard(run, p); };
      var t = this.now();
      this.log('admin', 'Approved version ' + rec.version, 'Approval starts the application step.');
      this.setState(function (s) {
        return {
          stage: 'applying', correction: 'applying', recovery: null,
          checks: blankChecks(), checksVersion: rec.version, testedWithoutContainment: false,
          times: Object.assign({}, s.times, { approved: t, applied: null, lifted: null, checked: null, restored: null, rolledBack: null })
        };
      });
      return this.safely(async function () {
        await g(self.svc.submitDecision(rec.id, 'approved'));
        await g(self.svc.applyCorrection(incId, rec));
        self.setState({ correction: 'applied', stage: 'verifying', containment: 'lifting' });
        self.mark('applied');
        self.log('system', 'Version ' + rec.version + ' applied to the firewall', rec.change);

        await g(self.svc.liftContainment(incId));
        self.setState({ containment: 'lifted', testedWithoutContainment: true,
          checks: { unauthorized_blocked: { status: 'running' }, legitimate_app: { status: 'running' } } });
        self.mark('lifted');
        self.log('system', 'Temporary block removed for testing', 'The permanent rule is now tested on its own.');

        var results = await g(Promise.all(TCC.CHECK_IDS.map(function (id) {
          return self.svc.runCheck(incId, id, rec).then(function (r) {
            if (run !== self.run) return r;
            self.setState(function (s) { var c = Object.assign({}, s.checks); c[id] = r; return { checks: c }; });
            self.log('system', (r.status === 'passed' ? 'Passed: ' : 'Failed: ') + TCC.CHECKS[id].name, r.detail);
            return r;
          });
        })));
        self.mark('checked');

        var failed = results.filter(function (r) { return r.status !== 'passed'; });
        if (!failed.length) {
          self.setState({ stage: 'resolved', correction: 'verified', containment: 'retired' });
          self.mark('resolved');
          self.log('system', 'Incident resolved', 'Both checks passed with the temporary block removed.');
          return;
        }

        // Failed: restore containment first (security), then roll back (availability).
        var summary = failed.map(function (r) {
          return '“' + TCC.CHECKS[r.id].name + '” failed: ' + (rec.failDetail || r.detail);
        }).join(' ');
        self.setState({
          stage: 'failed', containment: 'restoring', correction: 'failed',
          lastFailure: { version: rec.version, ids: failed.map(function (r) { return r.id; }), summary: summary, detail: rec.failDetail || failed[0].detail },
          recovery: { containment: 'running', rollback: 'pending' }
        });
        await g(self.svc.restoreContainment(incId));
        self.setState(function (s) {
          return { containment: 'active', correction: 'rolling_back', recovery: Object.assign({}, s.recovery, { containment: 'done', rollback: 'running' }) };
        });
        self.mark('restored');
        self.log('system', 'Temporary block restored', self.state.incident.source.name + ' is blocked from the database again while the fix is revised.');
        await g(self.svc.rollbackCorrection(incId, rec));
        self.setState(function (s) {
          return { correction: 'rolled_back', recovery: Object.assign({}, s.recovery, { rollback: 'done' }) };
        });
        self.mark('rolledBack');
        self.log('system', 'Version ' + rec.version + ' rolled back', 'Previous rules restored, so the application can reach the database again.');
      });
    }

    reject() {
      if (this.state.stage !== 'awaiting') return;
      var rec = this.state.rec, self = this;
      this.log('admin', 'Rejected version ' + rec.version, 'Not applied. The temporary block stays active.');
      this.setState({ stage: 'rejected', correction: 'rejected' });
      this.safely(function () { return self.svc.submitDecision(rec.id, 'rejected'); });
    }

    requestAnother() {
      if (this.state.stage !== 'rejected') return;
      var v = this.state.rec.version, run = this.run, self = this;
      this.log('admin', 'Asked the AI for another recommendation', 'Requested a different approach than version ' + v + '.');
      this.safely(function () { return self.draft(run, { type: 'rejected', version: v }); });
    }

    sendFeedback() {
      var s = this.state;
      if (s.stage !== 'failed' || !s.recovery || s.recovery.rollback !== 'done') return;
      var run = this.run, f = s.lastFailure, self = this;
      this.log('admin', 'Sent test results to the AI', f.summary);
      this.safely(function () { return self.draft(run, { type: 'failed', version: f.version, summary: f.summary }); });
    }

    toggleDetails() { this.setState({ showDetails: !this.state.showDetails }); }
  }

  TCC.IncidentWorkflow = IncidentWorkflow;
})(window.TCC);
