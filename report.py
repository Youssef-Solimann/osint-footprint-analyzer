"""
HTML report generation.

Turns the same `report` dict everything else already populates into a
single self-contained HTML file - inline CSS only, no external requests,
no JS framework, so it opens and reads correctly offline with nothing but
a browser. Deliberately built last: every other check feeds it, so this is
the piece that actually turns raw recon output into something that reads
like an assessment.

Every value that originated from an external source (WHOIS text,
subdomains, breach titles, redirect targets) goes through html.escape()
before being embedded - none of that text is under our control, and this
is a security tool, so treating it as untrusted by default is the right
default even though it's just rendered to a local file.

Colors are CSS variable references, not raw hex, so a single severity/
confidence value renders correctly in both light and dark mode without
the Python side needing to know which theme is active.
"""

import html
from urllib.parse import quote as url_quote

import utils

_SEVERITY_COLORS = {
    "Low": "var(--sev-low)", "Medium": "var(--sev-medium)",
    "High": "var(--sev-high)", "Critical": "var(--sev-critical)",
}
_CONFIDENCE_COLORS = {
    "High": "var(--conf-high)", "Medium": "var(--conf-medium)", "Low": "var(--conf-low)",
}
_SECTION_LABELS = {
    "summary": "Summary", "risk": "Assessment", "correlations": "Correlations",
    "username": "Username", "domain": "Domain", "email": "Email", "exif": "Image", "dorks": "Dorks",
}

_REPORT_CSS = """
:root {
  --bg: #f2f4f1; --panel: #fbfcfa; --hairline: #d7dcd3; --fg: #16211f; --muted: #5c6960;
  --accent: #0f6e5c; --ok: #2f9e44; --bad: #b42318; --bad-bg: #fdecea;
  --sev-low: #2f9e44; --sev-medium: #b8860b; --sev-high: #c2610c; --sev-critical: #b42318;
  --conf-high: #0f6e5c; --conf-medium: #b8860b; --conf-low: #5c6960;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101513; --panel: #171d1b; --hairline: #2a332f; --fg: #e7ece9; --muted: #93a39b;
    --accent: #35b897; --ok: #51cf66; --bad: #ff6b6b; --bad-bg: #2a1512;
    --sev-low: #51cf66; --sev-medium: #e0b341; --sev-high: #ff922b; --sev-critical: #ff6b6b;
    --conf-high: #35b897; --conf-medium: #e0b341; --conf-low: #93a39b;
  }
}
:root[data-theme="dark"] {
  --bg: #101513; --panel: #171d1b; --hairline: #2a332f; --fg: #e7ece9; --muted: #93a39b;
  --accent: #35b897; --ok: #51cf66; --bad: #ff6b6b; --bad-bg: #2a1512;
  --sev-low: #51cf66; --sev-medium: #e0b341; --sev-high: #ff922b; --sev-critical: #ff6b6b;
  --conf-high: #35b897; --conf-medium: #e0b341; --conf-low: #93a39b;
}
:root[data-theme="light"] {
  --bg: #f2f4f1; --panel: #fbfcfa; --hairline: #d7dcd3; --fg: #16211f; --muted: #5c6960;
  --accent: #0f6e5c; --ok: #2f9e44; --bad: #b42318; --bad-bg: #fdecea;
  --sev-low: #2f9e44; --sev-medium: #b8860b; --sev-high: #c2610c; --sev-critical: #b42318;
  --conf-high: #0f6e5c; --conf-medium: #b8860b; --conf-low: #5c6960;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); line-height: 1.55; font-family: var(--sans); font-size: 15px; }
a { color: var(--accent); }
a:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.report {
  max-width: 1080px; margin: 0 auto; padding: 2.5rem 1.5rem 5rem;
  display: grid; grid-template-columns: 250px 1fr; gap: 2.25rem; align-items: start;
}
.sidebar {
  position: sticky; top: 2rem; background: var(--panel); border: 1px solid var(--hairline);
  border-radius: 8px; padding: 1.5rem;
}
.wordmark { font-family: var(--mono); font-weight: 700; font-size: 1rem; letter-spacing: 0.01em; }
.wordmark .sub {
  display: block; font-weight: 500; color: var(--muted); font-size: 0.66rem;
  letter-spacing: 0.14em; text-transform: uppercase; margin-top: 0.25rem;
}
.identity { margin: 1.25rem 0; display: flex; flex-direction: column; gap: 0.5rem; }
.identity-row { display: flex; justify-content: space-between; gap: 0.75rem; }
.identity-row .k {
  font-family: var(--mono); color: var(--muted); text-transform: uppercase;
  font-size: 0.64rem; letter-spacing: 0.07em; padding-top: 0.2rem; white-space: nowrap;
}
.identity-row .v { text-align: right; font-weight: 600; font-size: 0.85rem; word-break: break-word; }
.gauge-block { border-top: 1px solid var(--hairline); padding-top: 1.25rem; margin-top: 0.25rem; }
.gauge { position: relative; width: 92px; height: 92px; margin: 0 auto; }
.gauge svg { width: 100%; height: 100%; }
.gauge-track { stroke: var(--hairline); stroke-width: 2.5; fill: none; }
.gauge-fill { stroke-width: 2.5; stroke-linecap: round; fill: none; }
.gauge-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.gauge-value .num { font-family: var(--mono); font-weight: 700; font-size: 1.3rem; font-variant-numeric: tabular-nums; }
.gauge-value .max { font-size: 0.6rem; color: var(--muted); margin-top: -0.15rem; }
.gauge-caption { text-align: center; margin-top: 0.6rem; }
.severity-pill {
  display: inline-block; color: #fff; font-family: var(--mono); font-weight: 600;
  font-size: 0.68rem; letter-spacing: 0.05em; text-transform: uppercase;
  padding: 0.2rem 0.6rem; border-radius: 3px;
}
.no-score { color: var(--muted); font-size: 0.85rem; text-align: center; padding: 1rem 0; margin: 0; }
.toc { display: flex; flex-direction: column; gap: 0.15rem; margin-top: 1.25rem; padding-top: 1.25rem; border-top: 1px solid var(--hairline); }
.toc-label { font-family: var(--mono); font-size: 0.64rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.4rem; }
.toc a { color: var(--fg); text-decoration: none; font-size: 0.85rem; padding: 0.25rem 0 0.25rem 0.6rem; border-left: 2px solid transparent; margin-left: -0.6rem; }
.toc a:hover, .toc a:focus-visible { border-left-color: var(--accent); color: var(--accent); }
.meta { font-size: 0.72rem; color: var(--muted); margin-top: 1.25rem; }
.main { display: flex; flex-direction: column; gap: 1.5rem; min-width: 0; }
.panel { background: var(--panel); border: 1px solid var(--hairline); border-radius: 8px; padding: 1.5rem 1.75rem; scroll-margin-top: 1.5rem; }
.panel h2 {
  margin: 0 0 1.1rem; font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.09em; color: var(--muted);
  display: flex; align-items: center; gap: 0.55rem;
}
.panel h2::before { content: ""; width: 0.42rem; height: 0.42rem; border-radius: 50%; flex-shrink: 0; background: var(--dot, var(--hairline)); }
.panel h3 { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; margin: 1.25rem 0 0.6rem; font-weight: 600; }
.panel h3:first-of-type { margin-top: 0; }
.muted { color: var(--muted); }
.small { font-size: 0.83rem; }
.ok { color: var(--ok); }
.bad { color: var(--bad); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
table.kv td, table.rules td { padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--hairline); vertical-align: top; text-align: left; }
table.kv tr:last-child td, table.rules tr:last-child td { border-bottom: none; }
table.kv tr:nth-child(even) td, table.rules tr:nth-child(even) td { background: rgba(127, 127, 127, 0.14); }
table.kv td:first-child { color: var(--muted); width: 32%; white-space: nowrap; font-size: 0.82rem; }
table.rules td.pts { font-family: var(--mono); font-weight: 700; width: 3.25rem; font-variant-numeric: tabular-nums; }
ul { padding-left: 1.1rem; margin: 0.5rem 0; }
ul.platform-list, ul.subdomain-list, ul.dorks, ul.breaches, ul.findings, ul.headers { list-style: none; padding-left: 0; margin: 0; }
ul.platform-list li, ul.subdomain-list li { padding: 0.4rem 0; border-bottom: 1px solid var(--hairline); font-size: 0.88rem; }
ul.platform-list li:last-child, ul.subdomain-list li:last-child { border-bottom: none; }
ul.platform-list a { color: var(--fg); text-decoration: none; font-weight: 600; }
ul.platform-list a:hover, ul.platform-list a:focus-visible { color: var(--accent); text-decoration: underline; }
li.finding { display: flex; gap: 0.65rem; align-items: flex-start; padding: 0.5rem 0; border-bottom: 1px solid var(--hairline); font-size: 0.88rem; }
li.finding:last-child { border-bottom: none; }
.badge {
  display: inline-block; color: #fff; font-family: var(--mono); font-size: 0.66rem; font-weight: 700;
  letter-spacing: 0.03em; text-transform: uppercase; padding: 0.2rem 0.5rem; border-radius: 3px;
  white-space: nowrap; margin-top: 0.1rem;
}
.badge.tech {
  background: transparent; border: 1px solid var(--hairline); color: var(--muted);
  margin: 0 0.35rem 0.35rem 0; font-weight: 600;
}
pre.raw-text {
  white-space: pre-wrap; word-break: break-word; font-family: var(--mono); font-size: 0.82rem;
  background: var(--bg); border: 1px solid var(--hairline); border-radius: 6px; padding: 0.75rem;
  margin: 0.5rem 0 0;
}
ul.headers li { padding: 0.2rem 0; font-size: 0.88rem; }
details summary { cursor: pointer; color: var(--muted); font-size: 0.82rem; margin-top: 0.75rem; font-family: var(--mono); text-transform: uppercase; letter-spacing: 0.04em; }
details[open] summary { margin-bottom: 0.5rem; }
/* value-details holds a truncated preview of real content (a CSP header,
   a TXT record dump) - the uppercase/mono treatment above is for short
   section labels like "Subdomains (12)", wrong tone for a text preview */
details.value-details { display: inline; }
details.value-details summary {
  display: inline; margin-top: 0; font-family: var(--sans); text-transform: none;
  letter-spacing: normal; font-size: inherit; color: inherit;
}
details.value-details[open] summary { margin-bottom: 0.35rem; display: block; }
details.value-details .raw-text { margin-top: 0.35rem; }
li.breach { border-bottom: 1px solid var(--hairline); padding: 0.6rem 0; font-size: 0.88rem; }
li.breach:last-child { border-bottom: none; }
.gps-warning {
  background: var(--bad-bg); border: 1px solid var(--bad); border-radius: 8px;
  padding: 1rem 1.25rem; margin-top: 0.75rem;
}
.gps-warning-title { margin: 0 0 0.6rem; color: var(--bad); font-weight: 700; font-size: 0.9rem; }
.gps-warning table.kv { background: transparent; }
.gps-warning table.kv tr:nth-child(even) td { background: rgba(127, 127, 127, 0.1); }
.gps-warning p:last-child { margin-bottom: 0; }
.report-footer {
  max-width: 1080px; margin: 1rem auto 0; padding: 1.5rem 1.5rem 2.5rem;
  text-align: center; color: var(--muted); font-size: 0.78rem; border-top: 1px solid var(--hairline);
}
@media (max-width: 860px) {
  .report { grid-template-columns: 1fr; }
  .sidebar { position: static; }
}
@media print {
  body { background: #fff; color: #000; }
  .report { grid-template-columns: 200px 1fr; }
  .sidebar { position: static; break-inside: avoid; }
  .toc { display: none; }
  .panel { break-inside: avoid; }
}
"""


def _panel(section_id, title, body_html, dot_color=None):
    dot_style = f' style="--dot:{dot_color}"' if dot_color else ""
    return f'<section class="panel" id="{section_id}"><h2{dot_style}>{html.escape(title)}</h2>{body_html}</section>'


# values longer than this collapse behind a <details> disclosure instead of
# dumping straight into the table - a full CSP header or a joined TXT record
# list can run past 500 characters and otherwise dominates the whole panel
_COLLAPSE_THRESHOLD = 100


def _collapsible_value(value, muted=True):
    text = str(value)
    escaped = html.escape(text)
    css = "muted small" if muted else ""
    if len(text) <= _COLLAPSE_THRESHOLD:
        return f'<span class="{css}">{escaped}</span>' if css else escaped
    preview = html.escape(text[:_COLLAPSE_THRESHOLD].rstrip()) + "…"
    summary_class = f' class="{css}"' if css else ""
    return (
        f'<details class="value-details"><summary{summary_class}>{preview}</summary>'
        f'<div class="raw-text">{escaped}</div></details>'
    )


def _html_sidebar(report, nav_html):
    target = report.get("target", {})
    rows = "".join(
        f'<div class="identity-row"><span class="k">{label}</span><span class="v">{html.escape(str(value))}</span></div>'
        for label, key in (("username", "username"), ("domain", "domain"), ("email", "email"), ("image", "image"))
        for value in [target.get(key)] if value
    )

    risk = report.get("risk_score")
    if risk:
        score = risk.get("score", 0)
        max_score = risk.get("max_score", 100)
        severity = risk.get("severity", "Low")
        color = _SEVERITY_COLORS.get(severity, "var(--conf-low)")
        pct = max(0, min(100, int(100 * score / max_score) if max_score else 0))
        gauge_html = f"""
        <div class="gauge-block">
          <div class="gauge">
            <svg viewBox="0 0 36 36">
              <circle class="gauge-track" cx="18" cy="18" r="15.9155" />
              <circle class="gauge-fill" cx="18" cy="18" r="15.9155"
                      stroke-dasharray="{pct} {100 - pct}" transform="rotate(-90 18 18)"
                      style="stroke:{color}" />
            </svg>
            <div class="gauge-value"><span class="num">{score}</span><span class="max">/ {max_score}</span></div>
          </div>
          <div class="gauge-caption"><span class="severity-pill" style="background:{color}">{html.escape(severity)}</span></div>
        </div>
        """
    else:
        gauge_html = '<div class="gauge-block"><p class="no-score">Not scored</p></div>'

    generated_at = html.escape(str(report.get("generated_at", "")))
    return f"""
    <aside class="sidebar">
      <div class="wordmark">OSINT FOOTPRINT<span class="sub">Analyzer &middot; Report</span></div>
      <div class="identity">{rows}</div>
      {gauge_html}
      <nav class="toc">
        <span class="toc-label">Contents</span>
        {nav_html}
      </nav>
      <div class="meta">Generated {generated_at}</div>
    </aside>
    """


def _html_executive_summary_section(report):
    """
    A 30-second-scan rollup at the top of the report, one line per
    category that actually ran - reads only from data every other
    section already computed, adds nothing new. Skips a category
    entirely rather than showing a fabricated "n/a" when it wasn't
    part of this scan, same philosophy as the correlations section
    skipping single-identifier runs.
    """
    rows = []

    username_results = report.get("username_results")
    if username_results:
        found = len(username_results.get("found", []))
        unclear = len(username_results.get("unclear", []))
        rows.append(("Username", f"{found} confirmed, {unclear} unclear"))

    domain_results = report.get("domain_results")
    if domain_results:
        present = domain_results.get("security_headers_present", {})
        missing = domain_results.get("security_headers_missing", [])
        total_headers = len(present) + len(missing)
        if total_headers:
            rows.append(("Domain", f"{len(present)}/{total_headers} security headers present"))
        subdomain_info = domain_results.get("subdomains", {})
        if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
            rows.append(("Subdomains", f"{len(subdomain_info.get('subdomains', []))} found"))

    email_results = report.get("email_results")
    if email_results:
        hibp = email_results.get("hibp", {})
        if hibp.get("checked"):
            breach_count = len(hibp.get("breaches", []))
            rows.append(("Email", f"{breach_count} known breach(es)" if breach_count else "No known breaches"))
        else:
            rows.append(("Email", "Breach check not performed"))

    exif_results = report.get("exif_results")
    if exif_results:
        if exif_results.get("gps"):
            rows.append(("Image", "GPS coordinates found"))
        elif exif_results.get("has_exif"):
            rows.append(("Image", "No GPS data"))
        else:
            rows.append(("Image", "No EXIF data"))

    risk = report.get("risk_score")
    if risk:
        rows.append(("Overall risk", f"{risk['score']}/{risk['max_score']} ({risk['severity']})"))

    if not rows:
        return ""

    row_html = "".join(
        f"<tr><td>{html.escape(label)}</td><td>{html.escape(value)}</td></tr>" for label, value in rows
    )
    body = f'<div class="table-wrap"><table class="kv">{row_html}</table></div>'
    return _panel("summary", "Executive Summary", body)


def _html_risk_section(risk):
    if not risk:
        return ""
    severity = risk.get("severity", "Low")
    color = _SEVERITY_COLORS.get(severity, "var(--conf-low)")
    triggered = risk.get("triggered_rules", [])
    if triggered:
        rows = "".join(
            f'<tr><td class="pts">+{html.escape(str(t["points"]))}</td>'
            f'<td>{html.escape(t["description"])}'
            f'<div class="muted small">{html.escape(t["recommendation"])}</div></td></tr>'
            for t in triggered
        )
        body = f'<div class="table-wrap"><table class="rules">{rows}</table></div>'
    else:
        body = '<p class="muted">No risk factors triggered.</p>'
    return _panel("risk", "Exposure Assessment", body, dot_color=color)


def _html_correlations_section(correlations):
    if correlations is None:
        return ""
    if not correlations:
        body = '<p class="muted">No direct correlations found between the supplied identifiers.</p>'
        return _panel("correlations", "Identifier Correlations", body)
    items = "".join(
        f'<li class="finding"><span class="badge" '
        f'style="background:{_CONFIDENCE_COLORS.get(c["confidence"], "var(--conf-low)")}">'
        f'{html.escape(c["confidence"])}</span><span>{html.escape(c["description"])}</span></li>'
        for c in correlations
    )
    body = f'<ul class="findings">{items}</ul>'
    return _panel("correlations", "Identifier Correlations", body, dot_color="var(--accent)")


def _html_username_section(results):
    if not results:
        return ""

    def render_group(entries):
        if not entries:
            return '<p class="muted small">None</p>'
        items = []
        for e in entries:
            platform = html.escape(e.get("platform", ""))
            url = html.escape(e.get("url", ""))
            notes = []
            if e.get("reason"):
                notes.append(html.escape(e["reason"]))
            if e.get("redirected_to"):
                notes.append(f'redirected to {html.escape(e["redirected_to"])}')
            notes_html = f'<div class="muted small">{" &middot; ".join(notes)}</div>' if notes else ""
            items.append(f'<li><a href="{url}" target="_blank" rel="noopener">{platform}</a>{notes_html}</li>')
        return f'<ul class="platform-list">{"".join(items)}</ul>'

    found = results.get("found", [])
    unclear = results.get("unclear", [])
    not_found = results.get("not_found", [])
    errors = results.get("error", [])
    errors_html = f'<details><summary>Errors ({len(errors)})</summary>{render_group(errors)}</details>' if errors else ""

    body = f"""
      <h3>Found ({len(found)})</h3>
      {render_group(found)}
      <details>
        <summary>Unclear ({len(unclear)})</summary>
        {render_group(unclear)}
      </details>
      <details>
        <summary>Not found ({len(not_found)})</summary>
        {render_group(not_found)}
      </details>
      {errors_html}
    """
    return _panel("username", "Username Footprint", body)


def _html_domain_section(results):
    if not results:
        return ""

    dns_records = results.get("dns_records", {})
    dns_note = ""
    if dns_records.get("skipped"):
        dns_note = f'<p class="muted small">{html.escape(str(dns_records.get("reason", "")))}</p>'
    elif dns_records.get("nxdomain"):
        dns_note = '<p class="bad small">Domain does not exist (NXDOMAIN)</p>'

    def _dns_value_cell(values):
        return _collapsible_value(", ".join(values), muted=False) if values else '<span class="muted">none</span>'

    dns_rows = "".join(
        f'<tr><td>{html.escape(rtype)}</td><td>{_dns_value_cell(values)}</td></tr>'
        for rtype, values in dns_records.items()
        if rtype not in ("nxdomain", "skipped", "reason")
    )

    whois_note = ""
    if results.get("whois"):
        whois_note = f'<p class="muted small">{html.escape(str(results["whois"]))}</p>'
    elif results.get("whois_error"):
        whois_note = f'<p class="muted small">WHOIS lookup failed: {html.escape(str(results["whois_error"]))}</p>'

    whois_rows = ""
    for label, key in (
        ("Registrar", "registrar"), ("Created", "creation_date"), ("Expires", "expiration_date"),
        ("Registrant name", "registrant_name"), ("Registrant org", "registrant_org"),
    ):
        value = results.get(key)
        if value:
            whois_rows += f"<tr><td>{label}</td><td>{html.escape(str(value))}</td></tr>"
    registrant_emails = results.get("registrant_emails") or []
    if registrant_emails:
        whois_rows += f'<tr><td>Registrant email(s)</td><td>{html.escape(", ".join(registrant_emails))}</td></tr>'
    name_servers = results.get("name_servers") or []
    if name_servers:
        whois_rows += f'<tr><td>Name servers</td><td>{html.escape(", ".join(str(n) for n in name_servers))}</td></tr>'
    whois_html = f'<div class="table-wrap"><table class="kv">{whois_rows}</table></div>' if whois_rows else whois_note

    present = results.get("security_headers_present", {})
    missing = results.get("security_headers_missing", [])
    headers_items = "".join(
        f'<li class="ok">&check; {html.escape(h)}: {_collapsible_value(v)}</li>'
        for h, v in present.items()
    )
    headers_items += "".join(f'<li class="bad">&cross; {html.escape(h)}</li>' for h in missing)
    headers_html = f'<ul class="headers">{headers_items}</ul>' if headers_items else ""

    redirect_chain = results.get("redirect_chain") or []
    redirect_html = (
        f'<p class="small muted">{" &rarr; ".join(html.escape(u) for u in redirect_chain)}</p>'
        if redirect_chain else ""
    )

    technologies = results.get("technologies") or []
    tech_html = (
        "".join(f'<span class="badge tech">{html.escape(t)}</span>' for t in technologies)
        if technologies else ""
    )

    def _email_sec_row(label, ok, record):
        css_class = "ok" if ok else "bad"
        mark = "&check;" if ok else "&cross;"
        detail = f': {_collapsible_value(record)}' if ok and record else ""
        return f'<li class="{css_class}">{mark} {label}{detail}</li>'

    email_sec = results.get("email_security") or {}
    if email_sec:
        email_sec_html = (
            "<ul class=\"headers\">"
            + _email_sec_row("SPF", email_sec.get("spf"), email_sec.get("spf_record"))
            + _email_sec_row("DMARC", email_sec.get("dmarc"), email_sec.get("dmarc_record"))
            + "</ul>"
        )
    else:
        email_sec_html = ""

    robots_disallow = results.get("robots_disallow") or []
    well_known_parts = []
    if robots_disallow:
        items = "".join(f"<li>{html.escape(d)}</li>" for d in robots_disallow)
        well_known_parts.append(
            f'<details><summary>robots.txt Disallow entries ({len(robots_disallow)})</summary>'
            f'<ul class="subdomain-list">{items}</ul></details>'
        )
    security_txt = results.get("security_txt")
    if security_txt:
        well_known_parts.append(
            f'<details><summary>security.txt</summary>'
            f'<pre class="raw-text">{html.escape(security_txt)}</pre></details>'
        )
    well_known_html = "".join(well_known_parts)

    subdomain_info = results.get("subdomains", {})
    sub_html = ""
    if isinstance(subdomain_info, dict) and subdomain_info.get("success"):
        sub_list = subdomain_info.get("subdomains", [])
        items = "".join(f"<li>{html.escape(s)}</li>" for s in sub_list)
        sub_html = (
            f'<details><summary>Subdomains ({len(sub_list)})</summary>'
            f'<ul class="subdomain-list">{items}</ul></details>'
        )
        cert = subdomain_info.get("latest_certificate")
        if cert:
            sub_html += (
                f'<p class="small muted">Latest certificate issued by '
                f'{html.escape(str(cert.get("issuer") or "unknown"))}, valid '
                f'{html.escape(str(cert.get("not_before") or "?"))} to '
                f'{html.escape(str(cert.get("not_after") or "?"))}</p>'
            )
    elif isinstance(subdomain_info, dict) and subdomain_info.get("reason"):
        sub_html = f'<p class="muted small">Subdomain lookup unavailable: {html.escape(subdomain_info["reason"])}</p>'

    body = f"""
      <h3>DNS Records</h3>
      {dns_note}
      <div class="table-wrap"><table class="kv">{dns_rows}</table></div>
      <h3>WHOIS</h3>
      {whois_html}
      <h3>Security Headers</h3>
      {headers_html}
      {redirect_html}
      {f'<h3>Technologies Detected</h3><div>{tech_html}</div>' if tech_html else ""}
      {f'<h3>Email Security</h3>{email_sec_html}' if email_sec_html else ""}
      {f'<h3>Well-Known Files</h3>{well_known_html}' if well_known_html else ""}
      {sub_html}
    """
    return _panel("domain", "Domain Recon", body)


def _html_email_section(results):
    if not results:
        return ""
    email_raw = results.get("email", "")
    valid = results.get("format_valid")
    mx = results.get("mx_records", [])
    hibp = results.get("hibp", {})
    dot = None

    if hibp.get("checked"):
        breaches = hibp.get("breaches", [])
        if breaches:
            dot = "var(--sev-high)"
            items = "".join(
                f'<li class="breach"><strong>{html.escape(b.get("title", ""))}</strong> '
                f'<span class="muted small">({html.escape(b.get("breach_date", ""))})</span>'
                f'<div class="muted small">Exposed: {html.escape(", ".join(b.get("data_classes", [])))}</div></li>'
                for b in breaches
            )
            hibp_html = f'<p class="bad">Breached in {len(breaches)} known breach(es):</p><ul class="breaches">{items}</ul>'
        else:
            hibp_html = '<p class="ok">No known breaches (HaveIBeenPwned)</p>'
    else:
        reason = hibp.get("reason") or "Not checked"
        hibp_html = f'<p class="muted">Breach check skipped: {html.escape(reason)}</p>'

    body = f"""
      <p>Format valid: {"&check; yes" if valid else "&cross; no"}</p>
      {f'<p>MX records: {html.escape(", ".join(mx))}</p>' if mx else ""}
      {hibp_html}
    """
    return _panel("email", f"Email: {email_raw}", body, dot_color=dot)


def _html_exif_section(results):
    if not results:
        return ""

    warnings = results.get("warnings") or []
    warnings_html = ""
    if warnings:
        items = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
        warnings_html = f'<h3>Notes</h3><ul class="muted small">{items}</ul>'

    if not results.get("has_exif"):
        file_name = html.escape(str(results.get("file", "")))
        body = f'<p class="muted small">{file_name}</p>' if file_name else ""
        body += warnings_html or '<p class="muted">No EXIF data present.</p>'
        return _panel("exif", "Image Metadata (EXIF)", body)

    rows = ""
    for label, key in (
        ("Format", "format"), ("Dimensions", "dimensions"), ("Camera make", "camera_make"),
        ("Camera model", "camera_model"), ("Created", "created"), ("Software", "software"),
    ):
        value = results.get(key)
        if value:
            rows += f"<tr><td>{label}</td><td>{html.escape(str(value))}</td></tr>"

    gps = results.get("gps")
    dot = None
    gps_html = ""
    if gps:
        dot = "var(--sev-high)"
        maps_url = html.escape(gps["maps_url"])
        gps_html = f"""
        <div class="gps-warning">
          <p class="gps-warning-title">Exact location embedded in image</p>
          <table class="kv">
            <tr><td>Latitude</td><td>{gps["latitude"]}</td></tr>
            <tr><td>Longitude</td><td>{gps["longitude"]}</td></tr>
          </table>
          <p><a href="{maps_url}" target="_blank" rel="noopener">View on map</a></p>
          <p class="muted small">Recommendation: strip EXIF metadata before sharing this photo publicly.</p>
        </div>
        """

    body = f'<div class="table-wrap"><table class="kv">{rows}</table></div>{gps_html}{warnings_html}'
    return _panel("exif", "Image Metadata (EXIF)", body, dot_color=dot)


def _html_dorks_section(dorks):
    if not dorks:
        return ""
    items = "".join(
        f'<li><a href="https://www.google.com/search?q={url_quote(d)}" target="_blank" rel="noopener">'
        f'{html.escape(d)}</a></li>'
        for d in dorks
    )
    body = f'<ul class="dorks">{items}</ul>'
    return _panel("dorks", "Suggested Manual Dorks", body)


def _html_footer():
    return f"""
    <footer class="report-footer">
      <p>Generated by OSINT Footprint Analyzer v{utils.VERSION} &middot; Local analysis</p>
    </footer>
    """


def generate_html_report(report):
    section_defs = [
        ("summary", _html_executive_summary_section(report)),
        ("risk", _html_risk_section(report.get("risk_score"))),
        ("correlations", _html_correlations_section(report.get("correlations"))),
        ("username", _html_username_section(report.get("username_results"))),
        ("domain", _html_domain_section(report.get("domain_results"))),
        ("email", _html_email_section(report.get("email_results"))),
        ("exif", _html_exif_section(report.get("exif_results"))),
        ("dorks", _html_dorks_section(report.get("suggested_dorks"))),
    ]
    present = [sid for sid, content in section_defs if content]
    nav_html = "".join(f'<a href="#{sid}">{_SECTION_LABELS[sid]}</a>' for sid in present)
    main_content = "\n".join(content for _, content in section_defs if content)
    sidebar = _html_sidebar(report, nav_html)
    footer = _html_footer()

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Footprint Report</title>
<style>
{_REPORT_CSS}
</style>
</head>
<body>
<div class="report">
{sidebar}
<main class="main">
{main_content}
</main>
</div>
{footer}
</body>
</html>
"""
