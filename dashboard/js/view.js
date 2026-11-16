/* View: turns workflow state into HTML. No side effects, no service calls.
   Buttons carry data-action="…"; main.js routes those clicks to the workflow. */
window.TCC = window.TCC || {};

(function (TCC) {
  'use strict';

  /* ---------- small helpers ---------- */
  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function clock(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  var SPIN = '<span class="spin" aria-hidden="true"></span>';
  function icon(glyph, spin) { return spin ? SPIN : (glyph ? '<span aria-hidden="true">' + esc(glyph) + '</span>' : ''); }
  function badge(tone, glyph, label, spin, extra) {
    return '<span class="badge tone-' + tone + (extra ? ' ' + extra : '') + '">' + icon(glyph, spin) + esc(label) + '</span>';
  }
  function checkBadge(st) {
    if (st === 'passed') return badge('green', '✓', 'Passed');
    if (st === 'failed') return badge('red', '✕', 'Failed');
    if (st === 'running') return badge('blue', '', 'Running', true);
    return badge('gray', '○', 'Not tested');
  }
  function summaryList(rows) {
    return '<dl class="summary">' + rows.map(function (r) {
      return '<div class="summary-row"><dt>' + esc(r[0]) + '</dt><dd>' + r[1] + '</dd></div>';
    }).join('') + '</dl>';
  }

  /* ---------- idle / detecting ---------- */
  function idleView() {
    return '<section class="card empty">' +
      '<span class="empty-icon" aria-hidden="true"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span>' +
      '<h1>No active incidents</h1>' +
      '<p>Watching for connections that break segmentation policy. Intended path: employee → company application → database.</p>' +
      '<p class="hint">Start a simulation from the demo bar at the top of the page.</p>' +
      '</section>';
  }
  function detectingView() {
    return '<section class="card empty detecting">' + SPIN.replace('spin"', 'spin spin-lg"') +
      '<span>Analyzing a flagged network connection…</span></section>';
  }

  /* ---------- incident header + tracker ---------- */
  function headerView(s) {
    var stage = s.stage;
    var overall = stage === 'resolved' ? badge('green', '✓', 'Resolved', false, 'badge-lg')
      : stage === 'failed' ? badge('red', '✕', 'Needs revision', false, 'badge-lg')
      : stage === 'awaiting' || stage === 'rejected' ? badge('amber', '!', 'Needs your action', false, 'badge-lg')
      : badge('blue', '', 'Automated response in progress', true, 'badge-lg');

    var labels = ['Detected', 'Contained', 'AI recommendation', 'Your approval', 'Applying', 'Verifying',
      stage === 'resolved' ? 'Resolved' : stage === 'failed' ? 'Needs revision' : 'Resolved / revision'];
    var cur = { containing: 1, recommending: 2, awaiting: 3, rejected: 3, applying: 4, verifying: 5, failed: 6, resolved: 7 }[stage];
    if (cur === undefined) cur = 0;

    var steps = labels.map(function (label, i) {
      var st = i < cur ? 'done' : i === cur ? 'current' : 'todo';
      if (stage === 'failed' && i >= 5) st = 'failed';
      if (stage === 'rejected' && i === 3) st = 'failed';
      var isCur = st === 'current' || (st === 'failed' && (i === 6 || stage === 'rejected'));
      var tone = st === 'done' ? 'green' : st === 'failed' ? 'red' : st === 'current' ? (stage === 'awaiting' ? 'amber' : 'teal') : 'todo';
      var glyph = st === 'done' ? '✓' : st === 'failed' ? '✕' : st === 'current' ? '●' : String(i + 1);
      return '<li' + (isCur ? ' aria-current="step"' : '') + '><span class="step tone-' + tone + (isCur ? ' is-current' : '') + '">' +
        '<span class="step-mark" aria-hidden="true">' + glyph + '</span>' + esc(label) +
        (isCur ? '<span class="step-now">· NOW</span>' : '') + '</span></li>';
    }).join('');

    return '<section class="card incident" aria-labelledby="h-incident">' +
      '<div class="incident-meta">' +
        '<span class="mono incident-id">' + esc(TCC.MOCK_INCIDENT.id) + '</span><span aria-hidden="true">·</span>' +
        '<span>Detected 25 Oct 2026, ' + clock(TCC.SIM_START) + '</span><span aria-hidden="true">·</span>' +
        '<span>Unauthorized connectivity</span>' +
        '<span class="push">' + overall + '</span>' +
      '</div>' +
      '<h1 id="h-incident">Employee workstation connected directly to the company database</h1>' +
      '<p class="lede">WS-FIN-042 bypassed the company application and opened a database connection, which a misconfigured firewall rule (#14) allowed. This is a policy violation; no data access has been observed or claimed.</p>' +
      '<ol class="tracker" aria-label="Response progress">' + steps + '</ol>' +
      '</section>';
  }

  /* ---------- three status tiles ---------- */
  function tile(q, tone, glyph, answer, sub, spin) {
    return '<div class="tile tone-' + tone + '">' +
      '<div class="tile-q">' + esc(q) + '</div>' +
      '<div class="tile-answer"><span class="tile-icon' + (spin ? ' is-spin' : '') + '" aria-hidden="true">' + (spin ? SPIN : esc(glyph)) + '</span>' +
      '<span>' + esc(answer) + '</span></div>' +
      '<div class="tile-sub">' + esc(sub) + '</div></div>';
  }
  function appIsBroken(s) {
    return s.checks.legitimate_app.status === 'failed' &&
      (s.stage === 'verifying' || (s.stage === 'failed' && s.correction !== 'rolled_back'));
  }
  function tilesView(s) {
    var c = s.containment, ub = s.checks.unauthorized_blocked.status, la = s.checks.legitimate_app.status;
    var version = s.rec ? s.rec.version : s.recs.length + 1;
    var Q1 = 'Is the threat contained?', Q2 = 'Permanent correction', Q3 = 'Company application';
    var threat;
    if (c === 'activating') threat = tile(Q1, 'blue', '', 'Blocking now…', 'Applying a temporary block to WS-FIN-042 only.', true);
    else if (c === 'active') threat = tile(Q1, 'green', '✓', 'Yes — temporary block', 'WS-FIN-042 cannot reach the database directly. Its application access still works.');
    else if (c === 'lifting') threat = tile(Q1, 'blue', '', 'Testing permanent rule', 'Temporary block being removed on purpose for an independent test.', true);
    else if (c === 'lifted' && ub === 'passed') threat = tile(Q1, 'green', '✓', 'Yes — permanent rule', 'Confirmed with the temporary block removed.');
    else if (c === 'lifted') threat = tile(Q1, 'blue', '', 'Testing permanent rule', 'Temporary block removed on purpose; checking the new rule alone.', true);
    else if (c === 'restoring') threat = tile(Q1, 'blue', '', 'Restoring temporary block…', 'Re-applied automatically after the failed check.', true);
    else if (c === 'retired') threat = tile(Q1, 'green', '✓', 'Yes — permanent rule', 'Verified. The temporary block is no longer needed.');
    else threat = tile(Q1, 'red', '✕', 'No — path is open', 'Rule #14 still allows the direct connection.');

    var corr = {
      none: tile(Q2, 'gray', '○', 'Not started', 'Proposed by the AI after containment.'),
      drafting: tile(Q2, 'blue', '', 'AI drafting version ' + version, 'Nothing changes until you approve.', true),
      proposed: tile(Q2, 'amber', '!', 'Waiting for your approval', 'Version ' + version + ' has not been applied.'),
      applying: tile(Q2, 'blue', '', 'Applying version ' + version, 'You approved it at ' + clock(s.times.approved) + '.', true),
      applied: tile(Q2, 'blue', '', 'Applied — being verified', 'Version ' + version + ' stays only if both checks pass.', true),
      verified: tile(Q2, 'green', '✓', 'In place and verified', 'Version ' + version + ' passed both checks.'),
      failed: tile(Q2, 'red', '✕', 'Version ' + version + ' failed a check', 'It will be rolled back automatically.'),
      rolling_back: tile(Q2, 'blue', '', 'Rolling back version ' + version, 'It failed a check.', true),
      rolled_back: tile(Q2, 'red', '✕', 'Version ' + version + ' rolled back', 'It failed a check. A revision is needed.'),
      rejected: tile(Q2, 'amber', '!', 'Rejected — not applied', 'Firewall unchanged. Ask the AI for another option.')
    }[s.correction];

    var app = la === 'running' ? tile(Q3, 'blue', '', 'Being tested', 'Requesting records through the application.', true)
      : appIsBroken(s) ? tile(Q3, 'red', '✕', 'Not working', 'Version ' + version + ' blocks it. Rolling back automatically.')
      : tile(Q3, 'green', '✓', 'Working', s.correction === 'rolled_back' ? 'Restored by rolling back the failed change.'
        : la === 'passed' ? 'Confirmed by verification.' : 'Not affected by the temporary block.');

    return '<section class="tiles" aria-label="Current state">' + threat + corr + app + '</section>';
  }

  /* ---------- current-step card ---------- */
  function item(status, text, time, sub) {
    var state = { done: 'Done', failed: 'Failed', running: 'In progress', pending: 'Waiting' }[status];
    var glyph = status === 'done' ? '✓' : status === 'failed' ? '✕' : '○';
    return '<li class="check-item is-' + status + '">' +
      '<span class="check-mark" aria-hidden="true">' + (status === 'running' ? SPIN : glyph) + '</span>' +
      '<div class="check-text"><div class="check-title">' + esc(text) + '</div>' + (sub ? '<div class="check-sub">' + esc(sub) + '</div>' : '') + '</div>' +
      '<span class="check-state">' + state + '</span>' +
      '<span class="check-time mono">' + (status === 'done' || status === 'failed' ? clock(time) : '') + '</span></li>';
  }

  function checksView(s) {
    var ok = s.testedWithoutContainment;
    var rows = TCC.CHECK_IDS.map(function (id, i) {
      var r = s.checks[id], def = TCC.CHECKS[id];
      var detail = r.status === 'running' ? def.running : r.status === 'not_tested' ? def.idle : r.detail;
      return '<div class="result is-' + r.status + '">' +
        '<div class="result-head"><span class="result-n">Check ' + (i + 1) + '</span><span class="result-name">' + esc(def.name) + '</span>' +
        '<span class="push">' + checkBadge(r.status) + '</span></div>' +
        '<div class="result-detail">' + esc(detail) + '</div>' +
        (r.evidence ? '<div class="result-evidence mono">' + esc(r.evidence) + '</div>' : '') +
        '</div>';
    }).join('');
    return '<div class="results">' +
      '<div class="results-head"><h3>Verification of version ' + esc(s.checksVersion) + '</h3>' +
      '<span class="condition ' + (ok ? 'is-ok' : '') + '"><span aria-hidden="true">' + (ok ? '✓ ' : '○ ') + '</span>' +
      (ok ? 'Tested with the temporary block removed' : 'Runs after the temporary block is removed') + '</span></div>' +
      rows + '</div>';
  }

  function ruleRows(rules) {
    return rules.map(function (r) {
      var cls = r.change === 'added' ? 'is-added' : r.change === 'removed' ? 'is-removed' : '';
      var tag = r.change === 'added' ? '+ Added' : r.change === 'removed' ? '– Removed' : '';
      return '<div class="rule ' + cls + '"><span class="mono rule-num">#' + esc(r.num) + '</span>' +
        '<span class="rule-action is-' + r.action + '">' + r.action.toUpperCase() + '</span>' +
        '<span class="mono rule-text">' + esc(r.src) + ' → ' + esc(r.dst) + ' · ' + esc(r.port) + '</span>' +
        (tag ? '<span class="rule-tag">' + tag + '</span>' : '') + '</div>';
    }).join('');
  }

  function approvalView(s) {
    var rec = s.rec, html = '';
    if (rec.revisedBecause) {
      var title = rec.revisedBecause === 'failed'
        ? 'Revised after version ' + rec.previousVersion + ' failed verification'
        : 'Revised after you rejected version ' + rec.previousVersion;
      html += '<div class="note note-amber"><div class="note-title">' + esc(title) + '</div>' +
        (rec.previousFailure ? '<p><strong>Previous result: </strong>' + esc(rec.previousFailure) + '</p>' : '') +
        '<p><strong>What changed: </strong>' + esc(rec.whatChanged) + '</p></div>';
    }
    html += '<div class="rec"><div class="overline">AI recommendation · version ' + esc(rec.version) + ' · local model (simulated)</div>' +
      '<p class="rec-summary">' + esc(rec.summary) + '</p></div>';
    html += summaryList([
      ['Rule change', esc(rec.change)],
      ['Will be blocked', esc(rec.affects)],
      ['Should keep working', esc(rec.unaffected)],
      ['After you approve', 'The rule is applied, the temporary block is removed, and two checks run: <em>attacker path blocked</em> and <em>application still works</em>. If either fails, the block is restored and the change is rolled back automatically.']
    ]);
    html += '<div class="disclosure">' +
      '<button type="button" class="link-btn" data-action="toggleDetails" data-key="toggleDetails" aria-expanded="' + s.showDetails + '" aria-controls="rule-details">' +
      '<span aria-hidden="true" class="chev">' + (s.showDetails ? '▾' : '▸') + '</span>' +
      (s.showDetails ? 'Hide rule changes' : 'Show rule changes and commands') + '</button>';
    if (s.showDetails) {
      html += '<div id="rule-details" class="rule-details"><div class="rule-cols">' +
        '<div><div class="rule-col-title">Before (current firewall, top to bottom)</div>' + ruleRows(rec.before) + '</div>' +
        '<div><div class="rule-col-title">After (proposed, top to bottom)</div>' + ruleRows(rec.after) + '</div></div>' +
        '<div class="commands mono">' + rec.commands.map(function (c) { return '<div>$ ' + esc(c) + '</div>'; }).join('') + '</div></div>';
    }
    return html + '</div>';
  }

  function stepCardView(s) {
    var stage = s.stage, rec = s.rec, T = s.times, c = s.containment;
    var version = rec ? rec.version : s.recs.length + 1;
    var ub = s.checks.unauthorized_blocked.status, la = s.checks.legitimate_app.status;
    var tone = 'gray', eyebrow = 'Automated — no action needed', title = '', sub = '', body = '';
    var bar = { hint: '', primary: null, secondary: null };   // primary: {label, action?, spin?}

    if (stage === 'containing' || stage === 'recommending') {
      var last = s.recs[s.recs.length - 1];
      var afterFailure = s.lastFailure && last && s.lastFailure.version === last.version;
      title = stage === 'containing' ? 'Containing the workstation' : (s.recs.length ? 'AI is drafting a revised recommendation' : 'AI is drafting a permanent fix');
      sub = 'The system is responding on its own. You will be asked to approve before any permanent firewall change.';
      body = '<ol class="checklist">' +
        item('done', 'Unauthorized connection detected', T.detected, 'WS-FIN-042 → DB-PRIMARY-01, tcp/5432') +
        item(c === 'activating' ? 'running' : 'done', 'Temporary block applied to WS-FIN-042 only', T.contained, 'Direct database access blocked; application access preserved') +
        item(stage === 'recommending' ? 'running' : 'pending', s.recs.length ? 'AI drafts version ' + version : 'AI drafts a permanent fix', null,
          afterFailure ? 'Using the failed test results from version ' + s.lastFailure.version
            : last ? 'Looking for a different approach than version ' + last.version
            : 'Local model reviews the incident and firewall rules') +
        '</ol>';
      bar = { hint: 'Nothing to do yet. This step finishes automatically.', primary: { label: 'Waiting for recommendation…', spin: true } };
    } else if (stage === 'awaiting') {
      tone = 'amber'; eyebrow = 'Your action needed';
      title = 'Review and approve version ' + version;
      sub = 'Nothing changes on the firewall until you approve. The temporary block stays active meanwhile.';
      body = approvalView(s);
      bar = { hint: 'Approving starts the application step. You will see each result here.',
        primary: { label: 'Approve and apply version ' + version, action: 'approve' },
        secondary: { label: 'Reject', action: 'reject' } };
    } else if (stage === 'rejected') {
      tone = 'amber'; eyebrow = 'Your action needed';
      title = 'Version ' + version + ' rejected — nothing was applied';
      sub = 'The workstation stays contained by the temporary block. Ask the AI for a different recommendation.';
      body = summaryList([
        ['Firewall', 'Unchanged. Version ' + esc(version) + ' was not applied.'],
        ['Temporary block', 'Still active. WS-FIN-042 cannot reach the database directly.'],
        ['Rejected proposal', esc(rec.summary)]
      ]);
      bar = { hint: 'The new version will need your approval too.', primary: { label: 'Ask AI for another recommendation', action: 'requestAnother' } };
    } else if (stage === 'applying' || stage === 'verifying') {
      title = (stage === 'applying' ? 'Applying version ' : 'Verifying version ') + version;
      sub = 'The temporary block is removed on purpose so the permanent rule is tested on its own.';
      var running = ub === 'running' || la === 'running';
      body = '<ol class="checklist">' +
        item('done', 'Approved by you', T.approved) +
        item(stage === 'applying' ? 'running' : 'done', 'Apply version ' + version + ' to the firewall', T.applied) +
        item(c === 'lifting' ? 'running' : T.lifted ? 'done' : 'pending', 'Remove temporary block for an independent test', T.lifted) +
        item(running ? 'running' : T.checked ? 'done' : 'pending', 'Run both checks', T.checked) +
        '</ol>' + checksView(s);
      bar = { hint: 'If a check fails, the system restores the temporary block and rolls back automatically.',
        primary: { label: stage === 'applying' ? 'Applying…' : 'Verifying…', spin: true } };
    } else if (stage === 'failed') {
      tone = 'red';
      var done = s.recovery && s.recovery.rollback === 'done', rc = s.recovery || {}, f = s.lastFailure;
      eyebrow = done ? 'Your action needed' : 'Needs revision — recovering automatically';
      title = 'Version ' + f.version + ' failed a check';
      sub = done ? 'Recovery is complete. Send the results to the AI so it can draft a corrected version.' : 'Restoring the temporary block, then rolling back the change.';
      body = '<ol class="checklist">' +
        item(rc.containment === 'done' ? 'done' : 'running', 'Restore temporary block on WS-FIN-042', T.restored) +
        item(rc.rollback === 'done' ? 'done' : rc.rollback === 'running' ? 'running' : 'pending', 'Roll back version ' + f.version + ' so the application works again', T.rolledBack) +
        item('pending', 'Send results to the AI for a revised version', null, 'Your step — the revision needs a new approval') +
        '</ol>' +
        '<div class="alert" role="alert"><span class="alert-mark" aria-hidden="true">✕</span><div>' +
        '<div class="alert-title">Failed: ' + esc(TCC.CHECKS[f.ids[0]].name) + '</div>' +
        '<p><strong>Why: </strong>' + esc(f.detail) + '</p>' +
        '<p><strong>What it means: </strong>the attacker path was closed, but the change also broke the company application, so version ' + esc(f.version) + ' cannot stay.</p>' +
        '</div></div>' + checksView(s);
      bar = done
        ? { hint: 'The AI uses the failed result to draft version ' + (s.recs.length + 1) + '.', primary: { label: 'Send test results to AI', action: 'sendFeedback' } }
        : { hint: 'Recovery runs automatically.', primary: { label: 'Recovering…', spin: true } };
    } else if (stage === 'resolved') {
      tone = 'green'; eyebrow = 'Resolved';
      title = 'Correction verified — incident resolved';
      sub = 'Both checks passed with the temporary block removed.';
      body = checksView(s) + summaryList([
        ['Permanent rule', 'Version ' + esc(version) + ': ' + esc(rec.change)],
        ['Temporary block', 'No longer needed; the verified rule blocks this traffic.'],
        ['What happens next', 'Monitoring continues. The full record is in the activity log.']
      ]);
      bar = { hint: 'No further action needed. Use Reset in the demo bar to run another scenario.' };
    }

    var attempt = '';
    var attemptNo = stage === 'recommending' ? s.recs.length + 1 : s.recs.length;
    if (attemptNo > 1) attempt = '<span class="attempt">Recommendation attempt ' + attemptNo + '</span>';

    var primary = '';
    if (bar.primary) {
      var p = bar.primary;
      primary = p.action
        ? '<button type="button" class="btn btn-primary" data-action="' + p.action + '" data-key="primary">' + esc(p.label) + '</button>'
        : '<button type="button" class="btn btn-primary" disabled data-key="primary">' + (p.spin ? SPIN : '') + esc(p.label) + '</button>';
    }
    var secondary = bar.secondary
      ? '<button type="button" class="btn btn-danger" data-action="' + bar.secondary.action + '" data-key="secondary">' + esc(bar.secondary.label) + '</button>'
      : '';

    return '<section class="card step-card tone-' + tone + '" aria-labelledby="h-step" aria-live="polite">' +
      '<div class="step-head">' +
        '<div class="step-eyebrow-row"><span class="eyebrow">' + esc(eyebrow) + '</span>' + attempt + '</div>' +
        '<h2 id="h-step">' + esc(title) + '</h2>' +
        '<p class="step-sub">' + esc(sub) + '</p>' +
      '</div>' +
      '<div class="step-body">' + body + '</div>' +
      '<div class="action-bar"><p class="action-hint">' + esc(bar.hint) + '</p>' +
        '<div class="action-buttons">' + secondary + primary + '</div></div>' +
      '</section>';
  }

  /* ---------- right column: details + activity ---------- */
  function sideView(s) {
    var c = s.containment, ub = s.checks.unauthorized_blocked.status;
    var appBadge = appIsBroken(s) ? badge('red', '✕', 'Broken by v' + s.rec.version) : badge('green', '✓', 'Allowed');
    var directBadge = c === 'active' ? badge('green', '✓', 'Blocked · temporary')
      : c === 'retired' || (c === 'lifted' && ub === 'passed') ? badge('green', '✓', 'Blocked · permanent rule')
      : c === 'off' ? badge('red', '✕', 'Open')
      : badge('blue', '', c === 'restoring' ? 'Restoring block…' : c === 'activating' ? 'Blocking…' : 'Testing…', true);

    var actors = { system: ['AUTOMATED', 'actor-system'], ai: ['AI MODEL', 'actor-ai'], admin: ['YOU', 'actor-admin'] };
    var log = s.timeline.length ? s.timeline.map(function (ev) {
      var a = actors[ev.actor];
      return '<li class="log-row"><span class="actor ' + a[1] + '">' + a[0] + '</span>' +
        '<div class="log-text"><div class="log-head"><span class="log-title">' + esc(ev.title) + '</span>' +
        '<time class="mono">' + clock(ev.at) + '</time></div>' +
        '<div class="log-detail">' + esc(ev.detail) + '</div></div></li>';
    }).join('') : '<li class="log-empty">No activity yet.</li>';

    return '<div class="side"><div class="side-inner">' +
      '<section class="card details" aria-labelledby="h-details"><h2 id="h-details">What happened</h2>' +
        '<div class="path"><div class="path-head"><span class="overline">Intended path</span><span class="push">' + appBadge + '</span></div>' +
        '<div>Workstation → <strong>APP-01</strong> (application) → <strong>DB-PRIMARY-01</strong></div></div>' +
        '<div class="path"><div class="path-head"><span class="overline">Unauthorized path</span><span class="push">' + directBadge + '</span></div>' +
        '<div><strong>WS-FIN-042</strong> → <strong>DB-PRIMARY-01</strong> directly, tcp/5432</div></div>' +
        '<dl class="facts">' +
          '<dt>Source</dt><dd>WS-FIN-042 · 10.20.0.42 (Employee LAN)</dd>' +
          '<dt>Target</dt><dd>DB-PRIMARY-01 · 10.30.0.10 (PostgreSQL)</dd>' +
          '<dt>Connection</dt><dd class="mono">10.20.0.42:51544 → 10.30.0.10:5432</dd>' +
          '<dt>Cause</dt><dd>Rule #14 allows the whole Employee LAN to reach the database</dd>' +
          '<dt>Seen by</dt><dd>Flow monitor, core switch</dd>' +
        '</dl></section>' +
      '<section class="card activity" aria-labelledby="h-time">' +
        '<div class="activity-head"><h2 id="h-time">Activity log</h2><span class="hint">Newest first · who did what</span></div>' +
        '<ol class="log">' + log + '</ol></section>' +
      '</div></div>';
  }

  /* ---------- public ---------- */
  TCC.renderApp = function (s) {
    if (s.stage === 'idle') return idleView();
    if (s.stage === 'detecting') return detectingView();
    return headerView(s) + tilesView(s) +
      '<div class="columns">' + stepCardView(s) + sideView(s) + '</div>';
  };
  TCC.demoStatus = function (s) {
    return s.scenario ? 'Running scenario ' + s.scenario + (s.scenario === 'A' ? ' (fix works)' : ' (first fix fails)') : 'No scenario running';
  };
})(window.TCC);
