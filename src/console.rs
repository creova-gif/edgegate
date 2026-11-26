//! EdgeGate Operator Console (HTML5 / Design System / Accessibility).
//!
//! Provides a self-contained, zero-external-dependency operator console
//! complying strictly with WCAG 2.1 AA+ and EdgeGate's Obsidian/Slate design language.

/// Strict Content Security Policy for the Operator Console.
pub const CONSOLE_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Returns the complete, self-contained static HTML5 document for `GET /_edgegate/console`.
pub fn render_operator_console_html() -> &'static str {
    OPERATOR_CONSOLE_HTML
}

static OPERATOR_CONSOLE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EdgeGate Operator Console — Zero-Secret L7 Security Gateway</title>
  <style>
    /* Design Tokens: Dark Theme Default (Obsidian & Slate Identity) */
    :root {
      --bg-canvas: #0d1117;
      --bg-surface: #161b22;
      --bg-elevated: #1f2630;
      --border-subtle: #30363d;
      --text-primary: #f0f6fc;
      --text-secondary: #c9d1d9;
      --text-dim: #8b949e;
      --accent-brand: #58a6ff;
      --accent-brand-focus: #388bfd;
      --status-ok: #3fb950;
      --status-ok-bg: #11281a;
      --status-warn: #d29922;
      --status-warn-bg: #2d2208;
      --status-err: #f85149;
      --status-err-bg: #321414;
      --purple-brand: #d2a8ff;
      --font-ui: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
      --radius-sm: 4px;
      --radius-md: 6px;
      --radius-lg: 8px;
    }

    /* Adaptive High-Contrast Light Theme Tokens */
    @media (prefers-color-scheme: light) {
      :root:not([data-theme="dark"]) {
        --bg-canvas: #f6f8fa;
        --bg-surface: #ffffff;
        --bg-elevated: #eaeef2;
        --border-subtle: #d0d7de;
        --text-primary: #1f2328;
        --text-secondary: #424a53;
        --text-dim: #57606a;
        --accent-brand: #0969da;
        --accent-brand-focus: #0550ae;
        --status-ok: #1a7f37;
        --status-ok-bg: #dafbe1;
        --status-warn: #9a6700;
        --status-warn-bg: #fff8c5;
        --status-err: #cf222e;
        --status-err-bg: #ffebe9;
        --purple-brand: #8250df;
      }
    }

    /* Explicit Manual Light Theme Override */
    :root[data-theme="light"] {
      --bg-canvas: #f6f8fa;
      --bg-surface: #ffffff;
      --bg-elevated: #eaeef2;
      --border-subtle: #d0d7de;
      --text-primary: #1f2328;
      --text-secondary: #424a53;
      --text-dim: #57606a;
      --accent-brand: #0969da;
      --accent-brand-focus: #0550ae;
      --status-ok: #1a7f37;
      --status-ok-bg: #dafbe1;
      --status-warn: #9a6700;
      --status-warn-bg: #fff8c5;
      --status-err: #cf222e;
      --status-err-bg: #ffebe9;
      --purple-brand: #8250df;
    }

    /* Explicit Manual Dark Theme Override */
    :root[data-theme="dark"] {
      --bg-canvas: #0d1117;
      --bg-surface: #161b22;
      --bg-elevated: #1f2630;
      --border-subtle: #30363d;
      --text-primary: #f0f6fc;
      --text-secondary: #c9d1d9;
      --text-dim: #8b949e;
      --accent-brand: #58a6ff;
      --accent-brand-focus: #388bfd;
      --status-ok: #3fb950;
      --status-ok-bg: #11281a;
      --status-warn: #d29922;
      --status-warn-bg: #2d2208;
      --status-err: #f85149;
      --status-err-bg: #321414;
      --purple-brand: #d2a8ff;
    }

    /* CSS Reset & Base Accessibility */
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      font-family: var(--font-ui);
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* High-visibility Keyboard Focus Indicator (WCAG 2.1 AA) */
    :focus-visible {
      outline: 2px solid var(--accent-brand);
      outline-offset: 2px;
    }

    /* Reduced Motion Preference (WCAG 2.1 AA) */
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
    }

    /* Screen Reader Only Utility */
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }

    /* Skip Navigation Link */
    .skip-link {
      position: absolute;
      top: -9999px;
      left: 1rem;
      background: var(--accent-brand);
      color: #0d1117;
      font-weight: 700;
      padding: 0.75rem 1.25rem;
      z-index: 10000;
      text-decoration: none;
      border-radius: var(--radius-sm);
      min-height: 44px;
      min-width: 44px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .skip-link:focus, .skip-link:focus-visible {
      top: 1rem;
      outline: 3px solid var(--text-primary);
    }

    /* Header Landmark */
    .console-header {
      background-color: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      padding: 1rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand-logo {
      width: 32px;
      height: 32px;
      flex-shrink: 0;
    }

    .brand-title-group h1 {
      font-size: 1.25rem;
      font-weight: 700;
      line-height: 1.2;
      color: var(--text-primary);
    }

    .brand-title-group p {
      font-size: 0.8rem;
      color: var(--text-dim);
    }

    .header-controls {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    /* Navigation Landmark */
    .console-nav {
      background-color: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.5rem 1.5rem;
      overflow-x: auto;
    }

    .nav-list {
      display: flex;
      list-style: none;
      gap: 0.75rem;
      align-items: center;
    }

    .nav-link {
      display: inline-flex;
      align-items: center;
      color: var(--text-secondary);
      text-decoration: none;
      padding: 0.5rem 0.75rem;
      border-radius: var(--radius-sm);
      font-weight: 600;
      font-size: 0.85rem;
      min-height: 44px;
      white-space: nowrap;
    }
    .nav-link:hover {
      color: var(--text-primary);
      background-color: var(--bg-elevated);
    }

    /* Main Container */
    main {
      flex: 1;
      padding: 1.5rem;
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    /* Cards */
    .console-card {
      background-color: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 1.25rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
    }

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border-subtle);
    }

    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .card-subtitle {
      font-size: 0.825rem;
      color: var(--text-dim);
      margin-top: 0.25rem;
    }

    /* KPI Grid Layout (Responsive: Mobile 320px+, Tablet 768px+, Desktop 1280px+) */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(1, 1fr);
      gap: 1rem;
    }

    @media (min-width: 540px) {
      .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (min-width: 768px) {
      .kpi-grid {
        grid-template-columns: repeat(3, 1fr);
      }
    }

    @media (min-width: 1280px) {
      .kpi-grid {
        grid-template-columns: repeat(5, 1fr);
      }
    }

    .kpi-tile {
      background-color: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 1rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.5rem;
    }

    .kpi-label {
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .kpi-value {
      font-size: 1.6rem;
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--text-primary);
      word-break: break-all;
    }

    /* Interactive Controls & Touch Accessibility (min 44px) */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.5rem 1rem;
      font-size: 0.875rem;
      font-weight: 600;
      font-family: inherit;
      border-radius: var(--radius-md);
      border: 1px solid transparent;
      cursor: pointer;
      min-height: 44px;
      min-width: 44px;
      text-decoration: none;
      transition: background-color 0.15s ease, border-color 0.15s ease;
    }

    .btn-primary {
      background-color: var(--accent-brand);
      color: #0d1117;
      border-color: var(--accent-brand-focus);
    }
    .btn-primary:hover {
      background-color: var(--accent-brand-focus);
    }

    .btn-secondary {
      background-color: var(--bg-elevated);
      color: var(--text-primary);
      border-color: var(--border-subtle);
    }
    .btn-secondary:hover {
      border-color: var(--text-dim);
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      margin-bottom: 1rem;
    }

    .form-label {
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-secondary);
    }

    .form-control {
      background-color: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 0.9rem;
      padding: 0.6rem 0.75rem;
      min-height: 44px;
      width: 100%;
    }
    .form-control:focus {
      border-color: var(--accent-brand);
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
    }

    @media (min-width: 768px) {
      .form-row {
        grid-template-columns: repeat(2, 1fr);
      }
      .form-row-3 {
        grid-template-columns: repeat(3, 1fr);
      }
    }

    /* Badges with Text Symbols (Status never conveyed by color alone) */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.5rem;
      border-radius: var(--radius-sm);
      font-size: 0.75rem;
      font-weight: 700;
      font-family: var(--font-mono);
      white-space: nowrap;
    }

    .badge-ok {
      background-color: var(--status-ok-bg);
      color: var(--status-ok);
      border: 1px solid var(--status-ok);
    }

    .badge-warn {
      background-color: var(--status-warn-bg);
      color: var(--status-warn);
      border: 1px solid var(--status-warn);
    }

    .badge-err {
      background-color: var(--status-err-bg);
      color: var(--status-err);
      border: 1px solid var(--status-err);
    }

    .badge-dim {
      background-color: var(--bg-elevated);
      color: var(--text-dim);
      border: 1px solid var(--border-subtle);
    }

    .badge-purple {
      background-color: var(--bg-elevated);
      color: var(--purple-brand);
      border: 1px solid var(--purple-brand);
    }

    /* Accessible Data Tables */
    .table-container {
      width: 100%;
      overflow-x: auto;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      background-color: var(--bg-surface);
    }

    .data-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }

    .data-table caption {
      padding: 0.75rem 1rem;
      font-weight: 700;
      font-size: 0.9rem;
      color: var(--text-secondary);
      text-align: left;
      background-color: var(--bg-elevated);
      border-bottom: 1px solid var(--border-subtle);
    }

    .data-table th, .data-table td {
      padding: 0.65rem 0.85rem;
      border-bottom: 1px solid var(--border-subtle);
      font-family: var(--font-mono);
    }

    .data-table th {
      background-color: var(--bg-elevated);
      color: var(--text-primary);
      font-weight: 700;
      white-space: nowrap;
    }

    .data-table tbody tr:hover {
      background-color: var(--bg-elevated);
    }

    /* Meter Bar for Prometheus Histograms */
    .meter-track {
      background-color: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      height: 14px;
      min-width: 120px;
      width: 100%;
      position: relative;
      overflow: hidden;
    }

    .meter-fill {
      background-color: var(--accent-brand);
      height: 100%;
      border-radius: 2px;
      transition: width 0.3s ease;
    }

    /* Footer Landmark */
    .console-footer {
      background-color: var(--bg-surface);
      border-top: 1px solid var(--border-subtle);
      padding: 1.25rem 1.5rem;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-dim);
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }

    .token-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
    }

    .token-input-wrapper {
      flex: 1;
      min-width: 240px;
    }
  </style>
</head>
<body>
  <!-- Accessible Skip Link (First Focusable Element) -->
  <a class="skip-link" href="#main-content">Skip to main content</a>

  <!-- Header Landmark -->
  <header class="console-header">
    <div class="brand-group">
      <!-- Inline SVG Logo: Zero external network request -->
      <svg class="brand-logo" viewBox="0 0 32 32" fill="none" aria-hidden="true">
        <rect width="32" height="32" rx="6" fill="#1f2630" stroke="#30363d"/>
        <path d="M16 6L24 10V16C24 21.5 20.5 25.5 16 27C11.5 25.5 8 21.5 8 16V10L16 6Z" fill="#161b22" stroke="#58a6ff" stroke-width="1.5"/>
        <path d="M13 16L15.5 18.5L20 13.5" stroke="#3fb950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div class="brand-title-group">
        <h1>EdgeGate Operator Console</h1>
        <p>Zero-Secret L7 Workload Egress Gateway &amp; Live Verification (v1.1.0)</p>
      </div>
    </div>
    <div class="header-controls">
      <button id="theme-toggle" type="button" class="btn btn-secondary" aria-pressed="false" aria-label="Toggle light or dark theme">
        <span id="theme-toggle-text">[Theme: Dark]</span>
      </button>
      <button id="btn-refresh" type="button" class="btn btn-secondary" aria-label="Refresh telemetry data now">
        <span>[Refresh Now]</span>
      </button>
      <span id="live-indicator" class="badge badge-ok" aria-label="Gateway connection status">[OK] Live Gateway</span>
    </div>
  </header>

  <!-- Navigation Landmark -->
  <nav aria-label="Console navigation" class="console-nav">
    <ul class="nav-list">
      <li><a class="nav-link" href="#sec-auth">Authentication</a></li>
      <li><a class="nav-link" href="#sec-kpi">Security KPIs</a></li>
      <li><a class="nav-link" href="#sec-latency">Latency Histogram</a></li>
      <li><a class="nav-link" href="#sec-pools">Upstream Pools</a></li>
      <li><a class="nav-link" href="#sec-audit">Audit Ledger</a></li>
      <li><a class="nav-link" href="#sec-replay">Incident Replay</a></li>
      <li><a class="nav-link" href="#sec-secrets">Secret Rotation</a></li>
    </ul>
  </nav>

  <!-- Live Screen Reader Announcement Region -->
  <div id="console-status" role="status" aria-live="polite" aria-atomic="true" class="sr-only">
    EdgeGate Operator Console ready. Polling active.
  </div>

  <!-- Main Content Landmark -->
  <main id="main-content" tabindex="-1">

    <!-- Operator Session Authentication Panel -->
    <section id="sec-auth" class="console-card" aria-labelledby="auth-heading">
      <div class="card-header">
        <div>
          <h2 id="auth-heading" class="card-title">Operator Control Plane Authentication</h2>
          <p id="auth-desc" class="card-subtitle">
            Enter administrative token for authorized access to <code>/_edgegate/admin/*</code> control plane APIs.
            Token is retained strictly in-memory in a JavaScript variable and <strong>never</strong> persisted to browser storage, disk storage, cookies, or URL parameters.
          </p>
        </div>
      </div>
      <div class="token-bar">
        <div class="token-input-wrapper">
          <label for="admin-token-input" class="form-label">X-EdgeGate-Admin-Token</label>
          <input type="password" id="admin-token-input" autocomplete="off" aria-describedby="auth-desc" placeholder="Enter administrative token..." class="form-control" />
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: flex-end;">
          <button id="btn-save-token" type="button" class="btn btn-primary" aria-label="Apply admin token in memory">[Set In-Memory Token]</button>
          <button id="btn-clear-token" type="button" class="btn btn-secondary" aria-label="Clear admin token from memory">[Clear Token]</button>
          <span id="token-status-badge" class="badge badge-dim" aria-label="In-memory token status">[NO TOKEN]</span>
        </div>
      </div>
    </section>

    <!-- Section 1: Liveness & Security Posture KPI Grid -->
    <section id="sec-kpi" class="console-card" aria-labelledby="kpi-heading">
      <div class="card-header">
        <div>
          <h2 id="kpi-heading" class="card-title">Liveness &amp; Security Posture KPIs</h2>
          <p class="card-subtitle">Live health verification and atomic configuration metrics (<code>/_edgegate/healthz</code> &amp; <code>/_edgegate/metrics</code>)</p>
        </div>
        <span id="kpi-poll-time" class="badge badge-dim" aria-label="Last poll timestamp">[Poll: --:--:--]</span>
      </div>
      <div class="kpi-grid">
        <div class="kpi-tile">
          <span class="kpi-label">Config Generation</span>
          <span id="kpi-config-gen" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Audit Chain Verdict</span>
          <div>
            <span id="kpi-audit-valid" class="badge badge-dim">[WAITING]</span>
          </div>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Allowed Requests</span>
          <span id="kpi-allowed" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Blocked Requests</span>
          <span id="kpi-blocked" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">DLP Blocked</span>
          <span id="kpi-dlp-blocked" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">JSON-RPC Blocked</span>
          <span id="kpi-jsonrpc-blocked" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Bulkhead Rejected</span>
          <span id="kpi-bulkhead-rejected" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Signed Requests</span>
          <span id="kpi-signed" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">Secret Reflections Blocked</span>
          <span id="kpi-reflections-blocked" class="kpi-value">0</span>
        </div>
        <div class="kpi-tile">
          <span class="kpi-label">In-Flight Requests</span>
          <span id="kpi-in-flight" class="kpi-value">0</span>
        </div>
      </div>
    </section>

    <!-- Section 2: Prometheus Latency Distribution Panel -->
    <section id="sec-latency" class="console-card" aria-labelledby="latency-heading">
      <div class="card-header">
        <div>
          <h2 id="latency-heading" class="card-title">Prometheus Latency Distribution</h2>
          <p class="card-subtitle">Parsed from Prometheus text exposition format (<code>/_edgegate/metrics?format=prometheus</code>)</p>
        </div>
        <div id="latency-summary" class="badge badge-purple" aria-label="Mean latency summary">[Count: 0 | Sum: 0 µs | Mean: 0 µs]</div>
      </div>
      <div class="table-container">
        <table aria-label="Request latency distribution" class="data-table">
          <caption>Request Duration Microsecond Buckets (Cumulative Distribution)</caption>
          <thead>
            <tr>
              <th scope="col">Upper Bound (le)</th>
              <th scope="col">Cumulative Count</th>
              <th scope="col">Proportion (%)</th>
              <th scope="col">Visual Distribution Meter</th>
            </tr>
          </thead>
          <tbody id="latency-tbody">
            <tr>
              <td colspan="4" style="text-align: center; color: var(--text-dim);">Awaiting Prometheus latency metric exposition...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Section 3: Upstream Pools & 3-State Circuit Breakers Table -->
    <section id="sec-pools" class="console-card" aria-labelledby="pools-heading">
      <div class="card-header">
        <div>
          <h2 id="pools-heading" class="card-title">Upstream Pools &amp; 3-State Circuit Breakers</h2>
          <p class="card-subtitle">Load balancing strategies, active health checks, and circuit states (<code>/_edgegate/admin/pools</code>)</p>
        </div>
      </div>
      <div class="table-container">
        <table aria-label="Upstream connection pools and circuit breakers" class="data-table">
          <caption>Upstream Backend Clusters, Load Balancing, and Circuit Breakers</caption>
          <thead>
            <tr>
              <th scope="col">Pool Name</th>
              <th scope="col">Strategy</th>
              <th scope="col">mTLS</th>
              <th scope="col">Backend ID</th>
              <th scope="col">Authority</th>
              <th scope="col">Weight</th>
              <th scope="col">Health</th>
              <th scope="col">In-Flight</th>
              <th scope="col">EWMA (µs)</th>
              <th scope="col">Circuit State</th>
            </tr>
          </thead>
          <tbody id="pools-tbody">
            <tr>
              <td colspan="10" style="text-align: center; color: var(--text-dim);">Admin token required to inspect upstream pool states.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Section 4: Cryptographic SHA-256 Hash-Chained Audit Ledger Explorer -->
    <section id="sec-audit" class="console-card" aria-labelledby="audit-heading">
      <div class="card-header">
        <div>
          <h2 id="audit-heading" class="card-title">Cryptographic Audit Ledger Explorer</h2>
          <p class="card-subtitle">Tamper-evident SHA-256 hash-chained request ledger (<code>/_edgegate/admin/audit</code>)</p>
        </div>
        <span id="audit-valid-status" class="badge badge-dim" aria-label="Cryptographic audit chain verification status">[WAITING]</span>
      </div>
      <div class="table-container">
        <table aria-label="Cryptographic SHA-256 hash-chained audit ledger" class="data-table">
          <caption>Cryptographic SHA-256 Audit Trail (Genesis to Head)</caption>
          <thead>
            <tr>
              <th scope="col">Seq</th>
              <th scope="col">Trace ID</th>
              <th scope="col">Org ID</th>
              <th scope="col">Workload ID</th>
              <th scope="col">Route</th>
              <th scope="col">Decision</th>
              <th scope="col">Status</th>
              <th scope="col">Hash Chain (Prev &rarr; Entry)</th>
            </tr>
          </thead>
          <tbody id="audit-tbody">
            <tr>
              <td colspan="8" style="text-align: center; color: var(--text-dim);">Admin token required to view cryptographic audit records.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Section 5: Sanitized Flight-Recorder Incident Replay Table -->
    <section id="sec-replay" class="console-card" aria-labelledby="replay-heading">
      <div class="card-header">
        <div>
          <h2 id="replay-heading" class="card-title">Flight-Recorder Incident Replay Buffer</h2>
          <p class="card-subtitle">Sanitized ring-buffer capturing policy violations, DLP, 429s, and 5xx errors (<code>/_edgegate/replay</code>)</p>
        </div>
      </div>
      <div class="table-container">
        <table aria-label="Flight-recorder incident replay records" class="data-table">
          <caption>Recent Intercepted Security Incidents and Anomalies</caption>
          <thead>
            <tr>
              <th scope="col">Req ID</th>
              <th scope="col">Trace ID</th>
              <th scope="col">Org / Workload</th>
              <th scope="col">Method</th>
              <th scope="col">Path</th>
              <th scope="col">Route</th>
              <th scope="col">Upstream</th>
              <th scope="col">Status</th>
              <th scope="col">Shadow</th>
              <th scope="col">Reason</th>
              <th scope="col">Latency (µs)</th>
            </tr>
          </thead>
          <tbody id="replay-tbody">
            <tr>
              <td colspan="11" style="text-align: center; color: var(--text-dim);">Awaiting incident records from flight-recorder buffer...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Section 6: Live Scoped Secret Rotation Form -->
    <section id="sec-secrets" class="console-card" aria-labelledby="secrets-heading">
      <div class="card-header">
        <div>
          <h2 id="secrets-heading" class="card-title">Live Scoped Secret Rotation</h2>
          <p class="card-subtitle">Rotate credentials atomically in memory without gateway downtime or configuration reloads (<code>POST /_edgegate/admin/secrets/rotate</code>)</p>
        </div>
      </div>
      <form id="rotate-form" novalidate>
        <div class="form-row form-row-3">
          <div class="form-group">
            <label for="rot-org" class="form-label">Tenant / Org ID *</label>
            <input type="text" id="rot-org" name="org_id" required placeholder="e.g. acme-corp" class="form-control" />
          </div>
          <div class="form-group">
            <label for="rot-ref" class="form-label">Credential Reference *</label>
            <input type="text" id="rot-ref" name="credential_ref" required placeholder="e.g. GITHUB_TOKEN" class="form-control" />
          </div>
          <div class="form-group">
            <label for="rot-expires" class="form-label">Optional Expiry (Epoch Seconds)</label>
            <input type="number" id="rot-expires" name="expires_at_epoch_s" placeholder="e.g. 1772000000" class="form-control" />
          </div>
        </div>
        <div class="form-group">
          <label for="rot-val" class="form-label">New Secret Value *</label>
          <input type="password" id="rot-val" name="value" required autocomplete="new-password" placeholder="Enter new secret payload..." class="form-control" />
        </div>
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-top: 0.5rem;">
          <button type="submit" id="btn-submit-rotate" class="btn btn-primary" aria-label="Rotate secret in gateway memory">[Rotate Secret In Memory]</button>
          <div id="rotate-feedback" role="status" aria-live="polite" class="badge badge-dim" style="display: none;"></div>
        </div>
      </form>
    </section>

  </main>

  <!-- Footer Landmark -->
  <footer class="console-footer">
    <div>
      <strong>EdgeGate Zero-Secret L7 Security Gateway</strong> &mdash; v1.1.0 High-Assurance Operator Interface
    </div>
    <div>
      <span>WCAG 2.1 AA+ Compliant</span> &bull; <span>Obsidian/Slate Design System</span>
    </div>
  </footer>

  <!-- Self-Contained JavaScript Logic (Safe DOM APIs, Zero InnerHTML with Untrusted Data) -->
  <script>
    (function() {
      "use strict";

      // In-Memory Token Storage: NEVER in browser storage, disk storage, cookies, or URL params
      let inMemoryAdminToken = "";

      // DOM Elements Cache
      const statusAnnouncer = document.getElementById("console-status");
      const themeToggleBtn = document.getElementById("theme-toggle");
      const themeToggleText = document.getElementById("theme-toggle-text");
      const btnRefresh = document.getElementById("btn-refresh");
      const adminTokenInput = document.getElementById("admin-token-input");
      const btnSaveToken = document.getElementById("btn-save-token");
      const btnClearToken = document.getElementById("btn-clear-token");
      const tokenStatusBadge = document.getElementById("token-status-badge");
      const liveIndicator = document.getElementById("live-indicator");

      // KPI Elements
      const kpiConfigGen = document.getElementById("kpi-config-gen");
      const kpiAuditValid = document.getElementById("kpi-audit-valid");
      const kpiAllowed = document.getElementById("kpi-allowed");
      const kpiBlocked = document.getElementById("kpi-blocked");
      const kpiDlpBlocked = document.getElementById("kpi-dlp-blocked");
      const kpiJsonrpcBlocked = document.getElementById("kpi-jsonrpc-blocked");
      const kpiBulkheadRejected = document.getElementById("kpi-bulkhead-rejected");
      const kpiSigned = document.getElementById("kpi-signed");
      const kpiReflectionsBlocked = document.getElementById("kpi-reflections-blocked");
      const kpiInFlight = document.getElementById("kpi-in-flight");
      const kpiPollTime = document.getElementById("kpi-poll-time");

      // Table Bodies
      const latencyTbody = document.getElementById("latency-tbody");
      const latencySummary = document.getElementById("latency-summary");
      const poolsTbody = document.getElementById("pools-tbody");
      const auditTbody = document.getElementById("audit-tbody");
      const auditValidStatus = document.getElementById("audit-valid-status");
      const replayTbody = document.getElementById("replay-tbody");

      // Rotate Form Elements
      const rotateForm = document.getElementById("rotate-form");
      const rotOrg = document.getElementById("rot-org");
      const rotRef = document.getElementById("rot-ref");
      const rotVal = document.getElementById("rot-val");
      const rotExpires = document.getElementById("rot-expires");
      const rotateFeedback = document.getElementById("rotate-feedback");

      // Live Region Announcement Helper
      function announce(msg) {
        if (statusAnnouncer) {
          statusAnnouncer.textContent = msg;
        }
      }

      // Safe Element Creation Helpers (Prevent DOM XSS)
      function createTextCell(text) {
        const td = document.createElement("td");
        td.textContent = text !== null && text !== undefined ? String(text) : "-";
        return td;
      }

      function createBadge(type, text) {
        const span = document.createElement("span");
        span.className = "badge " + type;
        span.textContent = text;
        return span;
      }

      // Theme Toggle Support (Accessible aria-pressed)
      let currentTheme = "dark";
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
        currentTheme = "light";
      }

      function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        currentTheme = theme;
        const isDark = theme === "dark";
        themeToggleBtn.setAttribute("aria-pressed", isDark ? "false" : "true");
        themeToggleText.textContent = isDark ? "[Theme: Dark]" : "[Theme: Light]";
        announce("Theme changed to " + theme + " mode.");
      }

      themeToggleBtn.addEventListener("click", function() {
        const next = currentTheme === "dark" ? "light" : "dark";
        applyTheme(next);
      });

      // Token Handlers
      btnSaveToken.addEventListener("click", function() {
        const val = adminTokenInput.value.trim();
        if (val.length > 0) {
          inMemoryAdminToken = val;
          tokenStatusBadge.className = "badge badge-ok";
          tokenStatusBadge.textContent = "[TOKEN SET]";
          announce("Admin token loaded into in-memory session.");
          pollAllEndpoints();
        } else {
          announce("Admin token cannot be empty.");
        }
      });

      btnClearToken.addEventListener("click", function() {
        inMemoryAdminToken = "";
        adminTokenInput.value = "";
        tokenStatusBadge.className = "badge badge-dim";
        tokenStatusBadge.textContent = "[NO TOKEN]";
        announce("In-memory admin token cleared.");
        pollAllEndpoints();
      });

      btnRefresh.addEventListener("click", function() {
        announce("Refreshing console data from EdgeGate APIs...");
        pollAllEndpoints();
      });

      // Headers Helper
      function getAuthHeaders() {
        const h = {};
        if (inMemoryAdminToken) {
          h["x-edgegate-admin-token"] = inMemoryAdminToken;
        }
        return h;
      }

      // Poll KPI & Health
      async function pollHealthAndMetrics() {
        try {
          const [hRes, mRes] = await Promise.all([
            fetch("/_edgegate/healthz"),
            fetch("/_edgegate/metrics", { headers: getAuthHeaders() })
          ]);

          if (hRes.ok) {
            const hData = await hRes.json();
            kpiConfigGen.textContent = String(hData.config_generation || 0);
            liveIndicator.className = "badge badge-ok";
            liveIndicator.textContent = "[OK] Live Gateway";
          } else {
            liveIndicator.className = "badge badge-err";
            liveIndicator.textContent = "[ERR] Gateway Offline";
          }

          if (mRes.ok) {
            const mData = await mRes.json();
            kpiAllowed.textContent = String(mData.allowed_total || 0);
            kpiBlocked.textContent = String(mData.blocked_total || 0);
            kpiDlpBlocked.textContent = String(mData.dlp_blocked_total || 0);
            kpiJsonrpcBlocked.textContent = String(mData.jsonrpc_blocked_total || 0);
            kpiBulkheadRejected.textContent = String(mData.bulkhead_rejected_total || 0);
            kpiSigned.textContent = String(mData.signed_requests_total || 0);
            kpiReflectionsBlocked.textContent = String(mData.secret_reflections_blocked_total || 0);
            kpiInFlight.textContent = String(mData.in_flight_requests || 0);

            if (mData.audit_chain_valid) {
              kpiAuditValid.className = "badge badge-ok";
              kpiAuditValid.textContent = "[OK] Valid";
            } else {
              kpiAuditValid.className = "badge badge-err";
              kpiAuditValid.textContent = "[BLOCKED] Corrupted";
            }
          }
          const now = new Date();
          kpiPollTime.textContent = "[Poll: " + now.toTimeString().split(" ")[0] + "]";
        } catch (err) {
          liveIndicator.className = "badge badge-err";
          liveIndicator.textContent = "[ERR] Network Error";
        }
      }

      // Poll Prometheus Latency Histogram
      async function pollPrometheusLatency() {
        try {
          const res = await fetch("/_edgegate/metrics?format=prometheus", { headers: getAuthHeaders() });
          if (!res.ok) return;
          const text = await res.text();
          const lines = text.split("\n");

          const buckets = [];
          let sumVal = 0;
          let countVal = 0;

          const bucketRegex = /^edgegate_request_duration_microseconds_bucket\{le="([^"]+)"\}\s+([0-9]+)/;
          const sumRegex = /^edgegate_request_duration_microseconds_sum\s+([0-9]+)/;
          const countRegex = /^edgegate_request_duration_microseconds_count\s+([0-9]+)/;

          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            const bMatch = line.match(bucketRegex);
            if (bMatch) {
              buckets.push({ le: bMatch[1], count: parseInt(bMatch[2], 10) });
              continue;
            }
            const sMatch = line.match(sumRegex);
            if (sMatch) {
              sumVal = parseInt(sMatch[1], 10);
              continue;
            }
            const cMatch = line.match(countRegex);
            if (cMatch) {
              countVal = parseInt(cMatch[1], 10);
            }
          }

          if (countVal > 0) {
            const mean = Math.round(sumVal / countVal);
            latencySummary.textContent = "[Count: " + countVal + " | Sum: " + sumVal + " µs | Mean: " + mean + " µs]";
          } else {
            latencySummary.textContent = "[Count: 0 | Sum: 0 µs | Mean: 0 µs]";
          }

          if (buckets.length > 0) {
            latencyTbody.textContent = "";
            const totalCount = countVal > 0 ? countVal : (buckets[buckets.length - 1].count || 1);

            buckets.forEach(function(b) {
              const tr = document.createElement("tr");

              const tdLe = createTextCell(b.le === "+Inf" ? "+Inf (All Latencies)" : "<= " + b.le + " µs");
              const tdCount = createTextCell(b.count);

              const pct = totalCount > 0 ? ((b.count / totalCount) * 100).toFixed(1) : "0.0";
              const tdPct = createTextCell(pct + "%");

              const tdMeter = document.createElement("td");
              const meterTrack = document.createElement("div");
              meterTrack.className = "meter-track";
              meterTrack.setAttribute("aria-hidden", "true");

              const meterFill = document.createElement("div");
              meterFill.className = "meter-fill";
              meterFill.style.width = Math.min(100, Math.max(0, parseFloat(pct))) + "%";

              meterTrack.appendChild(meterFill);
              tdMeter.appendChild(meterTrack);

              tr.appendChild(tdLe);
              tr.appendChild(tdCount);
              tr.appendChild(tdPct);
              tr.appendChild(tdMeter);

              latencyTbody.appendChild(tr);
            });
          }
        } catch (e) {
          // Keep prior state
        }
      }

      // Poll Upstream Pools
      async function pollPools() {
        if (!inMemoryAdminToken) {
          poolsTbody.textContent = "";
          const tr = document.createElement("tr");
          const td = document.createElement("td");
          td.colSpan = 10;
          td.style.textAlign = "center";
          td.style.color = "var(--text-dim)";
          td.textContent = "Admin token required to inspect upstream pool states.";
          tr.appendChild(td);
          poolsTbody.appendChild(tr);
          return;
        }

        try {
          const res = await fetch("/_edgegate/admin/pools", { headers: getAuthHeaders() });
          if (!res.ok) {
            poolsTbody.textContent = "";
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 10;
            td.style.textAlign = "center";
            td.style.color = "var(--status-err)";
            td.textContent = "[BLOCKED] Unauthorized: Check X-EdgeGate-Admin-Token.";
            tr.appendChild(td);
            poolsTbody.appendChild(tr);
            return;
          }

          const data = await res.json();
          poolsTbody.textContent = "";

          const pools = data.pools || [];
          if (pools.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 10;
            td.style.textAlign = "center";
            td.style.color = "var(--text-dim)";
            td.textContent = "No upstream pools configured.";
            tr.appendChild(td);
            poolsTbody.appendChild(tr);
            return;
          }

          pools.forEach(function(pool) {
            const backends = pool.backends || [];
            backends.forEach(function(b) {
              const tr = document.createElement("tr");

              tr.appendChild(createTextCell(pool.name));
              tr.appendChild(createTextCell(pool.strategy));

              const mtlsCell = document.createElement("td");
              mtlsCell.appendChild(pool.mtls_enabled ? createBadge("badge-ok", "[OK] mTLS") : createBadge("badge-dim", "[OFF]"));
              tr.appendChild(mtlsCell);

              tr.appendChild(createTextCell(b.id));
              tr.appendChild(createTextCell(b.authority));
              tr.appendChild(createTextCell(b.weight));

              const healthCell = document.createElement("td");
              healthCell.appendChild(b.active_healthy ? createBadge("badge-ok", "[OK] Healthy") : createBadge("badge-err", "[ERR] Degraded"));
              tr.appendChild(healthCell);

              tr.appendChild(createTextCell(b.in_flight));
              tr.appendChild(createTextCell(b.ewma_latency_us));

              const circuitCell = document.createElement("td");
              if (b.circuit_state === "closed") {
                circuitCell.appendChild(createBadge("badge-ok", "[OK] Closed"));
              } else if (b.circuit_state === "half_open") {
                circuitCell.appendChild(createBadge("badge-warn", "[HALF-OPEN]"));
              } else {
                circuitCell.appendChild(createBadge("badge-err", "[OPEN] Trip"));
              }
              tr.appendChild(circuitCell);

              poolsTbody.appendChild(tr);
            });
          });
        } catch (e) {
          // network error handled gracefully
        }
      }

      // Poll Audit Ledger
      async function pollAudit() {
        if (!inMemoryAdminToken) {
          auditTbody.textContent = "";
          const tr = document.createElement("tr");
          const td = document.createElement("td");
          td.colSpan = 8;
          td.style.textAlign = "center";
          td.style.color = "var(--text-dim)";
          td.textContent = "Admin token required to view cryptographic audit records.";
          tr.appendChild(td);
          auditTbody.appendChild(tr);
          auditValidStatus.className = "badge badge-dim";
          auditValidStatus.textContent = "[WAITING]";
          return;
        }

        try {
          const res = await fetch("/_edgegate/admin/audit", { headers: getAuthHeaders() });
          if (!res.ok) {
            auditTbody.textContent = "";
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 8;
            td.style.textAlign = "center";
            td.style.color = "var(--status-err)";
            td.textContent = "[BLOCKED] Unauthorized: Check X-EdgeGate-Admin-Token.";
            tr.appendChild(td);
            auditTbody.appendChild(tr);
            auditValidStatus.className = "badge badge-err";
            auditValidStatus.textContent = "[BLOCKED] Unauthorized";
            return;
          }

          const data = await res.json();
          if (data.valid) {
            auditValidStatus.className = "badge badge-ok";
            auditValidStatus.textContent = "[OK] SHA-256 Chain Valid";
          } else {
            auditValidStatus.className = "badge badge-err";
            auditValidStatus.textContent = "[ERR] Hash Mismatch";
          }

          auditTbody.textContent = "";
          const entries = data.entries || [];
          if (entries.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 8;
            td.style.textAlign = "center";
            td.style.color = "var(--text-dim)";
            td.textContent = "Audit ledger is currently empty (Genesis state).";
            tr.appendChild(td);
            auditTbody.appendChild(tr);
            return;
          }

          // Show latest entries first
          const slice = entries.slice(-15).reverse();
          slice.forEach(function(e) {
            const tr = document.createElement("tr");

            tr.appendChild(createTextCell(e.seq));
            tr.appendChild(createTextCell(e.trace_id));
            tr.appendChild(createTextCell(e.org_id));
            tr.appendChild(createTextCell(e.workload_id));
            tr.appendChild(createTextCell(e.route));

            const decCell = document.createElement("td");
            if (e.decision === "allow") {
              decCell.appendChild(createBadge("badge-ok", "[OK] ALLOW"));
            } else {
              decCell.appendChild(createBadge("badge-err", "[BLOCKED] DENY"));
            }
            tr.appendChild(decCell);

            tr.appendChild(createTextCell(e.status));

            const prevShort = e.prev_hash ? e.prev_hash.slice(0, 8) + "…" : "00000000…";
            const entryShort = e.entry_hash ? e.entry_hash.slice(0, 8) + "…" : "--------…";
            tr.appendChild(createTextCell(prevShort + " -> " + entryShort));

            auditTbody.appendChild(tr);
          });
        } catch (e) {
          // network error handled gracefully
        }
      }

      // Poll Replay Incident Buffer
      async function pollReplay() {
        try {
          const res = await fetch("/_edgegate/replay", { headers: getAuthHeaders() });
          if (!res.ok) return;

          const data = await res.json();
          const records = data.records || [];
          replayTbody.textContent = "";

          if (records.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 11;
            td.style.textAlign = "center";
            td.style.color = "var(--text-dim)";
            td.textContent = "No recent incident replay records in buffer.";
            tr.appendChild(td);
            replayTbody.appendChild(tr);
            return;
          }

          const slice = records.slice(-15).reverse();
          slice.forEach(function(r) {
            const tr = document.createElement("tr");

            tr.appendChild(createTextCell(r.request_id));
            tr.appendChild(createTextCell(r.trace_id));
            tr.appendChild(createTextCell(r.org_id + " / " + r.workload_id));
            tr.appendChild(createTextCell(r.method));
            tr.appendChild(createTextCell(r.path));
            tr.appendChild(createTextCell(r.route));
            tr.appendChild(createTextCell(r.upstream));

            const statusCell = document.createElement("td");
            if (r.status >= 200 && r.status < 300) {
              statusCell.appendChild(createBadge("badge-ok", "[" + r.status + " OK]"));
            } else if (r.status === 429) {
              statusCell.appendChild(createBadge("badge-warn", "[429 LIMIT]"));
            } else {
              statusCell.appendChild(createBadge("badge-err", "[" + r.status + " BLOCKED]"));
            }
            tr.appendChild(statusCell);

            tr.appendChild(createTextCell(r.shadow_status !== null ? r.shadow_status : "-"));
            tr.appendChild(createTextCell(r.reason));
            tr.appendChild(createTextCell(r.latency_us));

            replayTbody.appendChild(tr);
          });
        } catch (e) {
          // network error handled gracefully
        }
      }

      // Master Poll Function
      function pollAllEndpoints() {
        pollHealthAndMetrics();
        pollPrometheusLatency();
        pollPools();
        pollAudit();
        pollReplay();
      }

      // Secret Rotation Form Submission Handler
      rotateForm.addEventListener("submit", async function(evt) {
        evt.preventDefault();

        const org = rotOrg.value.trim();
        const ref = rotRef.value.trim();
        const val = rotVal.value;
        const expStr = rotExpires.value.trim();

        if (!org || !ref || !val) {
          rotateFeedback.style.display = "inline-flex";
          rotateFeedback.className = "badge badge-err";
          rotateFeedback.textContent = "[ERR] Org ID, Credential Ref, and Secret Value are all required.";
          announce("Secret rotation validation error: missing required fields.");
          return;
        }

        if (!inMemoryAdminToken) {
          rotateFeedback.style.display = "inline-flex";
          rotateFeedback.className = "badge badge-err";
          rotateFeedback.textContent = "[BLOCKED] Admin token required for secret rotation.";
          announce("Admin token required for secret rotation.");
          return;
        }

        const payload = {
          org_id: org,
          credential_ref: ref,
          value: val
        };

        if (expStr.length > 0) {
          const expNum = parseInt(expStr, 10);
          if (!isNaN(expNum)) {
            payload.expires_at_epoch_s = expNum;
          }
        }

        try {
          const res = await fetch("/_edgegate/admin/secrets/rotate", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-edgegate-admin-token": inMemoryAdminToken
            },
            body: JSON.stringify(payload)
          });

          if (res.ok) {
            rotVal.value = "";
            rotateFeedback.style.display = "inline-flex";
            rotateFeedback.className = "badge badge-ok";
            rotateFeedback.textContent = "[OK] Secret " + ref + " for " + org + " rotated in memory.";
            announce("Secret " + ref + " rotated successfully in memory.");
            pollAllEndpoints();
          } else {
            const errData = await res.json().catch(function() { return { error: "Rotation failed" }; });
            rotateFeedback.style.display = "inline-flex";
            rotateFeedback.className = "badge badge-err";
            rotateFeedback.textContent = "[ERR] " + (errData.error || "Rotation failed (" + res.status + ")");
            announce("Secret rotation failed: " + (errData.error || res.status));
          }
        } catch (e) {
          rotateFeedback.style.display = "inline-flex";
          rotateFeedback.className = "badge badge-err";
          rotateFeedback.textContent = "[ERR] Network transport error.";
          announce("Network transport error during secret rotation.");
        }
      });

      // Initial execution and recurring poll interval (every 5 seconds)
      pollAllEndpoints();
      setInterval(pollAllEndpoints, 5000);
    })();
  </script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_csp_contract() {
        assert_eq!(
            CONSOLE_CSP,
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn test_render_operator_console_html_non_empty() {
        let html = render_operator_console_html();
        assert!(!html.is_empty());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_wcag_landmarks_and_semantics() {
        let html = render_operator_console_html();

        // 1. Core Metadata
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(html
            .contains("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"));
        assert!(html.contains(
            "<title>EdgeGate Operator Console — Zero-Secret L7 Security Gateway</title>"
        ));

        // 2. Keyboard Skip Link
        assert!(
            html.contains("<a class=\"skip-link\" href=\"#main-content\">Skip to main content</a>")
        );

        // 3. Semantic Landmarks
        assert!(html.contains("<header class=\"console-header\">"));
        assert!(html.contains("<nav aria-label=\"Console navigation\""));
        assert!(html.contains("<main id=\"main-content\" tabindex=\"-1\">"));
        assert!(html.contains("<footer class=\"console-footer\">"));

        // 4. Live Screen-Reader Announcement Region
        assert!(html.contains("id=\"console-status\""));
        assert!(html.contains("role=\"status\""));
        assert!(html.contains("aria-live=\"polite\""));
        assert!(html.contains("aria-atomic=\"true\""));

        // 5. Accessible Form Controls with Explicit Labels
        assert!(html.contains("<label for=\"admin-token-input\""));
        assert!(html.contains("id=\"admin-token-input\""));
        assert!(html.contains("aria-describedby=\"auth-desc\""));
        assert!(html.contains("<label for=\"rot-org\""));
        assert!(html.contains("<label for=\"rot-ref\""));
        assert!(html.contains("<label for=\"rot-val\""));

        // 6. Accessible Table Structure with Captions and Column Headers
        assert!(html.contains(
            "<caption>Request Duration Microsecond Buckets (Cumulative Distribution)</caption>"
        ));
        assert!(html.contains(
            "<caption>Upstream Backend Clusters, Load Balancing, and Circuit Breakers</caption>"
        ));
        assert!(
            html.contains("<caption>Cryptographic SHA-256 Audit Trail (Genesis to Head)</caption>")
        );
        assert!(
            html.contains("<caption>Recent Intercepted Security Incidents and Anomalies</caption>")
        );
        assert!(html.contains("<th scope=\"col\">"));

        // 7. Text + Symbol Status Badges (Never Color Alone)
        assert!(html.contains("[OK]"));
        assert!(html.contains("[OPEN]"));
        assert!(html.contains("[HALF-OPEN]"));
        assert!(html.contains("[BLOCKED]"));

        // 8. Focus indicator & touch targets
        assert!(html.contains(":focus-visible"));
        assert!(html.contains("min-height: 44px"));
        assert!(html.contains("prefers-reduced-motion"));
        assert!(html.contains("prefers-color-scheme: light"));
    }

    #[test]
    fn test_zero_external_network_dependencies() {
        let html = render_operator_console_html();

        // Must not contain any external http/https URLs (zero CDN, external fonts, or external scripts)
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("cdn."));
        assert!(!html.contains("cdnjs"));
        assert!(!html.contains("unpkg"));
        assert!(!html.contains("jsdelivr"));
        assert!(!html.contains("googleapis"));

        // Must strictly avoid client storage
        assert!(!html.contains("localStorage"));
        assert!(!html.contains("sessionStorage"));
    }

    #[test]
    fn test_brand_tokens_and_endpoints_present() {
        let html = render_operator_console_html();

        // Obsidian/Slate Brand Palette
        assert!(html.contains("#0d1117"));
        assert!(html.contains("#161b22"));
        assert!(html.contains("#1f2630"));
        assert!(html.contains("#30363d"));
        assert!(html.contains("#f0f6fc"));
        assert!(html.contains("#c9d1d9"));
        assert!(html.contains("#58a6ff"));
        assert!(html.contains("#3fb950"));
        assert!(html.contains("#d29922"));
        assert!(html.contains("#f85149"));

        // Endpoints fetched by console
        assert!(html.contains("/_edgegate/healthz"));
        assert!(html.contains("/_edgegate/metrics"));
        assert!(html.contains("/_edgegate/metrics?format=prometheus"));
        assert!(html.contains("/_edgegate/admin/pools"));
        assert!(html.contains("/_edgegate/admin/audit"));
        assert!(html.contains("/_edgegate/replay"));
        assert!(html.contains("/_edgegate/admin/secrets/rotate"));

        // Admin token header
        assert!(html.contains("x-edgegate-admin-token"));
    }
}
