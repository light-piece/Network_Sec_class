/* =====================================================================
   DATA CONTRACTS — mirror these as Pydantic models in FastAPI.
   ---------------------------------------------------------------------
   Incident        { id, detectedAt(ms), source, target, app, connection, policy }
   Containment     { status:'active'|'lifted', ruleId, ruleText }
   Rule            { num, action:'allow'|'deny', src, dst, port, note, change:'unchanged'|'added'|'removed' }
   Recommendation  { id, version, model, summary, change, affects, unaffected,
                     before:Rule[], after:Rule[], commands:string[], whatChanged,
                     failDetail?, revisedBecause:null|'rejected'|'failed',
                     previousFailure:null|string, previousVersion:null|number }
   CheckResult     { id:'unauthorized_blocked'|'legitimate_app',
                     status:'not_tested'|'running'|'passed'|'failed', detail, evidence }
   ===================================================================== */
window.TCC = window.TCC || {};

(function (TCC) {
  'use strict';

  var SPEED = { slow: 1.6, normal: 1, fast: 0.35 };
  var SIM_START = new Date(2026, 9, 25, 14, 32, 7).getTime();
  var CHECK_IDS = ['unauthorized_blocked', 'legitimate_app'];

  /* ---------- mock data ---------- */
  var MOCK_INCIDENT = {
    id: 'INC-2026-0147',
    source: { name: 'WS-FIN-042', role: 'Employee workstation', ip: '10.20.0.42', segment: 'Employee LAN 10.20.0.0/24' },
    target: { name: 'DB-PRIMARY-01', role: 'Company database', ip: '10.30.0.10', segment: 'Data segment 10.30.0.0/24' },
    app: { name: 'APP-01', role: 'Company application', ip: '10.10.0.15', segment: 'Application segment 10.10.0.0/24' },
    connection: { protocol: 'TCP', srcPort: 51544, dstPort: 5432, service: 'PostgreSQL', observedBy: 'Flow monitor, core switch' },
    policy: { ruleId: '14', ruleText: 'allow 10.20.0.0/24 → 10.30.0.10 tcp/5432', intendedPath: 'Employee → company application → database' }
  };

  function rule(num, action, src, dst, port, note, change) {
    return { num: num, action: action, src: src, dst: dst, port: port, note: note, change: change || 'unchanged' };
  }
  var R10 = rule('10', 'allow', 'Employee LAN', 'APP-01', 'tcp/443', 'Employees use the application');
  var R12 = rule('12', 'allow', 'APP-01', 'DB-PRIMARY-01', 'tcp/5432', 'Application uses the database');
  var R14_BAD = rule('14', 'allow', 'Employee LAN', 'DB-PRIMARY-01', 'tcp/5432', 'Misconfigured', 'removed');
  var R99 = rule('99', 'deny', 'any', 'any', 'any', 'Default deny');
  var BEFORE = [R10, R12, R14_BAD, R99];

  var REC_LIBRARY = {
    good: {
      summary: 'Replace rule #14 with a rule that denies direct database connections from the Employee LAN.',
      change: 'Rule #14 changes from “allow Employee LAN → database” to “deny Employee LAN → database” (tcp/5432, logged).',
      affects: 'Direct database connections from every host on the Employee LAN (10.20.0.0/24), including WS-FIN-042.',
      unaffected: 'Employees using the company application (rule #10), and the application’s own database connection (rule #12).',
      before: BEFORE,
      after: [R10, R12, rule('14', 'deny', 'Employee LAN', 'DB-PRIMARY-01', 'tcp/5432', 'New', 'added'), R99],
      commands: ['fw rule delete 14', 'fw rule insert 14 deny src 10.20.0.0/24 dst 10.30.0.10 proto tcp dport 5432 log'],
      blockedBy: 'rule #14 (deny)',
      outcome: { unauthorized_blocked: 'pass', legitimate_app: 'pass' },
      whatChanged: ''
    },
    alt: {
      summary: 'Delete rule #14 and let the existing default-deny rule block direct database connections.',
      change: 'Rule #14 (allow Employee LAN → database) is deleted. No rule is added.',
      affects: 'Direct database connections from every host on the Employee LAN (10.20.0.0/24), including WS-FIN-042.',
      unaffected: 'Employees using the company application (rule #10), and the application’s own database connection (rule #12).',
      before: BEFORE,
      after: [R10, R12, R99],
      commands: ['fw rule delete 14'],
      blockedBy: 'rule #99 (default deny)',
      outcome: { unauthorized_blocked: 'pass', legitimate_app: 'pass' },
      whatChanged: 'Instead of adding a deny rule, this version only deletes rule #14 and relies on the existing default-deny rule #99.'
    },
    flawed: {
      summary: 'Delete rule #14 and add a broad rule that stops every internal address from connecting to the database directly.',
      change: 'Delete rule #14. Insert rule #11: deny 10.0.0.0/8 → database (tcp/5432, logged).',
      affects: 'Database connections from every internal address in 10.0.0.0/8.',
      unaffected: 'Employees using the company application (rule #10).',
      before: BEFORE,
      after: [R10, rule('11', 'deny', '10.0.0.0/8 (all internal)', 'DB-PRIMARY-01', 'tcp/5432', 'New', 'added'), R12, R99],
      commands: ['fw rule delete 14', 'fw rule insert 11 deny src 10.0.0.0/8 dst 10.30.0.10 proto tcp dport 5432 log'],
      blockedBy: 'rule #11 (deny)',
      outcome: { unauthorized_blocked: 'pass', legitimate_app: 'fail' },
      failDetail: 'New rule #11 (deny 10.0.0.0/8) is checked before the allow rule #12, and it also matches the application server 10.10.0.15. The application could not reach the database.',
      failEvidence: 'GET /api/records → 500 · database connection timed out after 5 s · APP-01 → 10.30.0.10:5432 matched rule #11 (deny)',
      whatChanged: ''
    },
    fixed: {
      summary: 'Delete rule #14 and deny direct database connections from the Employee LAN only, placed after the application’s allow rule.',
      change: 'Delete rule #14. Insert rule #13: deny Employee LAN 10.20.0.0/24 → database (tcp/5432, logged), below rule #12.',
      affects: 'Direct database connections from the Employee LAN (10.20.0.0/24) only, including WS-FIN-042.',
      unaffected: 'The application server (matched first by rule #12) and every other internal segment.',
      before: BEFORE,
      after: [R10, R12, rule('13', 'deny', 'Employee LAN', 'DB-PRIMARY-01', 'tcp/5432', 'New', 'added'), R99],
      commands: ['fw rule delete 14', 'fw rule insert 13 deny src 10.20.0.0/24 dst 10.30.0.10 proto tcp dport 5432 log'],
      blockedBy: 'rule #13 (deny)',
      outcome: { unauthorized_blocked: 'pass', legitimate_app: 'pass' },
      whatChanged: 'The deny rule now covers only the Employee LAN instead of all of 10.0.0.0/8, and it sits below the application’s allow rule #12, so the application server is allowed first.'
    }
  };
  /* Which recommendation the simulated AI returns on each attempt. */
  var SEQUENCES = { A: ['good', 'alt'], B: ['flawed', 'fixed'] };

  /* Check definitions (names and descriptions shown in the UI). */
  var CHECKS = {
    unauthorized_blocked: {
      name: 'Attacker path blocked',
      idle: 'Try a direct connection from WS-FIN-042 to the database. Expected: refused.',
      running: 'Trying a direct connection from WS-FIN-042 to the database…',
      pass: function (rec) { return { detail: 'The direct connection from WS-FIN-042 was refused.', evidence: '10.20.0.42 → 10.30.0.10:5432 · refused by ' + rec.blockedBy }; },
      fail: function () { return { detail: 'WS-FIN-042 could still connect to the database directly.', evidence: '10.20.0.42 → 10.30.0.10:5432 · connection established' }; }
    },
    legitimate_app: {
      name: 'Company application still works',
      idle: 'Request records through the company application. Expected: records returned.',
      running: 'Requesting records through the company application…',
      pass: function () { return { detail: 'The application returned 25 records normally.', evidence: 'GET /api/records → 200 OK · 142 ms · APP-01 → DB allowed by rule #12' }; },
      fail: function (rec) { return { detail: 'The application could not reach the database.', evidence: rec.failEvidence }; }
    }
  };

  /* =====================================================================
     SIMULATED SERVICE — every method returns a Promise and maps to a
     future FastAPI endpoint. ApiResponseService (api-service.js) has the
     same method names and return shapes.
     ===================================================================== */
  class MockResponseService {
    constructor(scenario, speedKey) {
      this.scenario = scenario || 'A';
      this.factor = SPEED[speedKey] || 1;
      this.attempt = 0;
    }
    delay(ms, value) {
      var f = this.factor;
      return new Promise(function (resolve) { setTimeout(function () { resolve(value); }, ms * f); });
    }
    // GET    /incidents/active
    getActiveIncident() { return this.delay(1200, Object.assign({}, MOCK_INCIDENT, { detectedAt: SIM_START })); }
    // POST   /incidents/{id}/containment
    activateContainment(incidentId) { return this.delay(2000, { status: 'active', ruleId: 'T-1', ruleText: 'deny 10.20.0.42 → 10.30.0.10 tcp/5432' }); }
    // DELETE /incidents/{id}/containment
    liftContainment(incidentId) { return this.delay(1600, { status: 'lifted' }); }
    // POST   /incidents/{id}/containment  (restore after a failed check)
    restoreContainment(incidentId) { return this.delay(1600, { status: 'active' }); }
    // POST   /incidents/{id}/recommendations   body { feedback }  → backend asks Ollama
    requestRecommendation(incidentId, feedback) {
      var seq = SEQUENCES[this.scenario];
      var key = seq[Math.min(this.attempt, seq.length - 1)];
      this.attempt += 1;
      return this.delay(feedback ? 3200 : 2800, Object.assign({}, REC_LIBRARY[key], {
        id: 'REC-' + this.attempt,
        version: this.attempt,
        model: 'Local model via Ollama (simulated)',
        revisedBecause: feedback ? feedback.type : null,
        previousVersion: feedback ? feedback.version : null,
        previousFailure: feedback && feedback.type === 'failed' ? feedback.summary : null
      }));
    }
    // POST   /recommendations/{id}/decision   body { decision: 'approved'|'rejected' }
    submitDecision(recId, decision) { return this.delay(400, { recId: recId, decision: decision }); }
    // POST   /incidents/{id}/corrections   body { recommendationId }
    applyCorrection(incidentId, rec) { return this.delay(2200, { status: 'applied', recId: rec.id }); }
    // POST   /corrections/{id}/rollback
    rollbackCorrection(incidentId, rec) { return this.delay(2000, { status: 'rolled_back', recId: rec.id }); }
    // POST   /incidents/{id}/verifications/{checkId}
    runCheck(incidentId, checkId, rec) {
      var def = CHECKS[checkId];
      var pass = rec.outcome[checkId] === 'pass';
      var r = pass ? def.pass(rec) : def.fail(rec);
      return this.delay(checkId === 'unauthorized_blocked' ? 2000 : 3200,
        { id: checkId, status: pass ? 'passed' : 'failed', detail: r.detail, evidence: r.evidence });
    }
  }

  TCC.SIM_START = SIM_START;
  TCC.CHECK_IDS = CHECK_IDS;
  TCC.CHECKS = CHECKS;
  TCC.MOCK_INCIDENT = MOCK_INCIDENT;
  TCC.MockResponseService = MockResponseService;
})(window.TCC);
