/* TNL Partner Portal 3.8.2 - legacy bundle (ERP plugin compatibility). Do not edit by hand. */
/* build: 2026.10.29-1742 (jenkins #881) */
(function () {
  "use strict";
  var cfg = {
    apiBase: "/api/v1",
    // TODO(ops, OPS-412): remove link preview helper once all ERP plugins use v2
    previewEndpoint: "/api/v1/preview?url=",
    // admin console moved in 3.7.4, old bookmarks still hit /admin
    adminPath: "/admin/login",
    sessionTimeoutHours: 8
  };
  window.TNL = window.TNL || {};
  window.TNL.config = cfg;
})();
