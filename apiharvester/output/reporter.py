"""Reporting — console, JSONL, and HTML output."""
import html as html_mod
import json
import os
import sys

from ..models import ScanContext


# ANSI colour codes
_COLORS = {
    "critical": "\033[91m",  # bright red
    "high":     "\033[31m",  # red
    "medium":   "\033[33m",  # yellow
    "low":      "\033[36m",  # cyan
    "info":     "\033[90m",  # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _sev_color(severity):
    return _COLORS.get(severity.lower(), "")


def report_console(ctx: ScanContext):
    """Print colour-coded findings to stderr."""
    findings = ctx.sorted_findings()
    if not findings:
        print(f"\n{_BOLD}No findings.{_RESET}\n", file=sys.stderr)
        return

    counts = {}
    print(f"\n{_BOLD}{'='*70}{_RESET}", file=sys.stderr)
    print(f"{_BOLD}  APISecScan Results — {ctx.target}  "
          f"({len(findings)} findings){_RESET}", file=sys.stderr)
    print(f"{_BOLD}{'='*70}{_RESET}\n", file=sys.stderr)

    for f in findings:
        sev = f.severity.upper()
        c = _sev_color(f.severity)
        counts[f.severity] = counts.get(f.severity, 0) + 1
        print(f"  {c}[{sev}]{_RESET} {_BOLD}{f.title}{_RESET}",
              file=sys.stderr)
        print(f"    Category : {f.category}", file=sys.stderr)
        print(f"    Endpoint : {f.method} {f.host}{f.path}", file=sys.stderr)
        print(f"    Status   : {f.status}", file=sys.stderr)
        if f.evidence:
            ev = f.evidence[:300]
            print(f"    Evidence : {ev}", file=sys.stderr)
        if f.remediation:
            print(f"    Fix      : {f.remediation}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"{_BOLD}Summary:{_RESET}", file=sys.stderr)
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            c = _sev_color(sev)
            print(f"  {c}{sev.upper():10s}: {n}{_RESET}", file=sys.stderr)
    print(file=sys.stderr)


def report_jsonl(ctx: ScanContext, path):
    """Write findings as JSONL."""
    findings = ctx.sorted_findings()
    with open(path, "w") as f:
        for finding in findings:
            f.write(finding.to_jsonl() + "\n")
    print(f"[*] JSONL report: {path} ({len(findings)} findings)",
          file=sys.stderr)


def report_html(ctx: ScanContext, path):
    """Write a self-contained styled HTML report."""
    findings = ctx.sorted_findings()
    sev_badge = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }

    rows = []
    for f in findings:
        color = sev_badge.get(f.severity.lower(), "#6c757d")
        rows.append(f"""<tr>
  <td><span class="badge" style="background:{color}">{html_mod.escape(f.severity.upper())}</span></td>
  <td>{html_mod.escape(f.title)}</td>
  <td>{html_mod.escape(f.category)}</td>
  <td><code>{html_mod.escape(f.method)} {html_mod.escape(f.host)}{html_mod.escape(f.path)}</code></td>
  <td>{f.status}</td>
  <td><small>{html_mod.escape((f.evidence or '')[:200])}</small></td>
  <td><small>{html_mod.escape(f.remediation or '')}</small></td>
</tr>""")

    table_rows = "\n".join(rows)
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>APISecScan Report — {html_mod.escape(ctx.target)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 2rem; background: #f8f9fa; color: #212529; }}
  h1 {{ border-bottom: 3px solid #343a40; padding-bottom: .5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem;
           background: white; box-shadow: 0 1px 3px rgba(0,0,0,.12); }}
  th, td {{ border: 1px solid #dee2e6; padding: .5rem .75rem; text-align: left;
            font-size: .875rem; vertical-align: top; }}
  th {{ background: #343a40; color: white; position: sticky; top: 0; }}
  tr:nth-child(even) {{ background: #f2f2f2; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 4px;
            font-weight: 700; font-size: .75rem; text-transform: uppercase; }}
  code {{ background: #e9ecef; padding: 1px 4px; border-radius: 3px;
          font-size: .8rem; word-break: break-all; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }}
  .summary div {{ background: white; padding: .75rem 1.25rem; border-radius: 6px;
                  box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 100px;
                  text-align: center; }}
  .summary .num {{ font-size: 1.5rem; font-weight: 700; }}
  .summary .label {{ font-size: .75rem; text-transform: uppercase; color: #6c757d; }}
</style>
</head>
<body>
<h1>APISecScan Report</h1>
<p><strong>Target:</strong> {html_mod.escape(ctx.target)} &nbsp;|&nbsp;
   <strong>Findings:</strong> {len(findings)} &nbsp;|&nbsp;
   <strong>Hosts:</strong> {len(ctx.active_hosts())} &nbsp;|&nbsp;
   <strong>Endpoints:</strong> {len(ctx.endpoints)}</p>

<div class="summary">
  {"".join(f'<div><div class="num" style="color:{sev_badge.get(s, "#6c757d")}">{sum(1 for f in findings if f.severity==s)}</div><div class="label">{s}</div></div>' for s in ("critical","high","medium","low","info") if any(f.severity==s for f in findings))}
</div>

<table>
<thead>
<tr><th>Severity</th><th>Title</th><th>Category</th><th>Endpoint</th>
    <th>Status</th><th>Evidence</th><th>Remediation</th></tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
<p style="margin-top:2rem;color:#6c757d;font-size:.75rem;">
  Generated by APISecScan &mdash; for authorized testing only.</p>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    print(f"[*] HTML report: {path} ({len(findings)} findings)",
          file=sys.stderr)
