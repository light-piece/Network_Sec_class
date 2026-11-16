/* Real backend client. Used when the backend answers (see config.js).
   Same method names and return shapes as MockResponseService, so the
   workflow and the UI do not change when you switch. Paths: docs/API_CONTRACT.md.
   On a non-2xx answer it throws an Error whose message is the API's `detail` text. */
window.TCC = window.TCC || {};

(function (TCC) {
  'use strict';

  /* The API's error body is {"detail": "..."} (FastAPI). Show that text to the administrator. */
  async function errorText(res, method, path) {
    var detail = null;
    try {
      var data = await res.json();
      detail = data && data.detail;
      if (Array.isArray(detail)) detail = detail.map(function (d) { return d.msg || JSON.stringify(d); }).join('; ');
      else if (detail && typeof detail !== 'string') detail = JSON.stringify(detail);
    } catch (e) { /* not JSON */ }
    return detail || (method + ' ' + path + ' failed: HTTP ' + res.status);
  }

  class ApiResponseService {
    constructor(baseUrl) { this.base = baseUrl.replace(/\/$/, ''); }

    async request(method, path, body) {
      var res;
      try {
        res = await fetch(this.base + path, {
          method: method,
          headers: body ? { 'Content-Type': 'application/json' } : undefined,
          body: body ? JSON.stringify(body) : undefined
        });
      } catch (e) {
        throw new Error('Cannot reach the backend (' + method + ' ' + path + '): ' + e.message);
      }
      if (!res.ok) throw new Error(await errorText(res, method, path));
      return res.status === 204 ? null : res.json();
    }

    getStatus()                             { return this.request('GET', '/status'); }
    runAttack()                             { return this.request('POST', '/lab/attack'); }
    resetLab()                              { return this.request('POST', '/lab/reset'); }

    getActiveIncident()                     { return this.request('GET', '/incidents/active'); }
    activateContainment(incidentId)         { return this.request('POST', '/incidents/' + incidentId + '/containment'); }
    liftContainment(incidentId)             { return this.request('DELETE', '/incidents/' + incidentId + '/containment'); }
    restoreContainment(incidentId)          { return this.request('POST', '/incidents/' + incidentId + '/containment'); }
    requestRecommendation(incidentId, fb)   { return this.request('POST', '/incidents/' + incidentId + '/recommendations', { feedback: fb || null }); }
    submitDecision(recId, decision)         { return this.request('POST', '/recommendations/' + recId + '/decision', { decision: decision }); }
    applyCorrection(incidentId, rec)        { return this.request('POST', '/incidents/' + incidentId + '/corrections', { recommendationId: rec.id }); }
    rollbackCorrection(incidentId, rec)     { return this.request('POST', '/incidents/' + incidentId + '/corrections/' + rec.id + '/rollback'); }
    runCheck(incidentId, checkId, rec)      { return this.request('POST', '/incidents/' + incidentId + '/verifications/' + checkId, { recommendationId: rec.id }); }
  }

  TCC.ApiResponseService = ApiResponseService;
})(window.TCC);
