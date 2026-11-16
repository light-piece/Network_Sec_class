/* Real backend client (week 2+). Not used while TCC.config.USE_MOCK is true.
   Same method names and return shapes as MockResponseService, so the
   workflow and the UI do not change when you switch. The endpoint paths are
   suggestions; adjust them to match your FastAPI routes. */
window.TCC = window.TCC || {};

(function (TCC) {
  'use strict';

  class ApiResponseService {
    constructor(baseUrl) { this.base = baseUrl.replace(/\/$/, ''); }

    async request(method, path, body) {
      const res = await fetch(this.base + path, {
        method: method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined
      });
      if (!res.ok) throw new Error(method + ' ' + path + ' failed: ' + res.status);
      return res.status === 204 ? null : res.json();
    }

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
