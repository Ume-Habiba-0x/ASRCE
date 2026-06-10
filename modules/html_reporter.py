import json
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ASRCE Report — {domain}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        h1 {{ margin-top: 0; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--card);
            padding: 20px;
            border-radius: 12px;
            border-left: 4px solid var(--muted);
        }}
        .card.critical {{ border-left-color: var(--critical); }}
        .card.high {{ border-left-color: var(--high); }}
        .card.medium {{ border-left-color: var(--medium); }}
        .card.low {{ border-left-color: var(--low); }}
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge.critical {{ background: rgba(239,68,68,0.2); color: var(--critical); }}
        .badge.high {{ background: rgba(249,115,22,0.2); color: var(--high); }}
        .badge.medium {{ background: rgba(234,179,8,0.2); color: var(--medium); }}
        .badge.low {{ background: rgba(34,197,94,0.2); color: var(--low); }}
        .meta {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 8px; }}
        .chart-container {{ max-width: 400px; margin: 0 auto 30px; }}
        .reason-tag {{
            display: inline-block;
            background: rgba(148,163,184,0.15);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 2px;
        }}
        .section-title {{
            margin-top: 40px;
            margin-bottom: 20px;
            font-size: 1.25rem;
            font-weight: 600;
        }}
        .host-row {{
            margin-bottom: 16px;
            padding-bottom: 16px;
            border-bottom: 1px solid #334155;
        }}
        .host-name {{ font-weight: 600; font-size: 1rem; margin-bottom: 4px; }}
        .host-meta {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 8px; }}
        .reasons {{ margin-top: 6px; }}
        .hidden {{ display: none; }}
        .tab-btn {{
            background: var(--card);
            border: none;
            color: var(--text);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            margin-right: 8px;
            margin-bottom: 10px;
        }}
        .tab-btn.active {{ background: #334155; }}
    </style>
</head>
<body>
    <h1>🔍 ASRCE Report</h1>
    <div class="meta">Generated: {generated_at} | Tool: {tool} | Domain: {domain}</div>
    
    <div class="grid">
        <div class="card">
            <div class="chart-container">
                <canvas id="riskChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h3>Summary</h3>
            <p>Total: <strong>{total}</strong> hosts</p>
            <p><span class="badge critical">Critical: {critical}</span></p>
            <p><span class="badge high">High: {high}</span></p>
            <p><span class="badge medium">Medium: {medium}</span></p>
            <p><span class="badge low">Low: {low}</span></p>
        </div>
    </div>

    <div>
        <button class="tab-btn active" onclick="showAll()">All</button>
        <button class="tab-btn" onclick="showSeverity('critical')">Critical</button>
        <button class="tab-btn" onclick="showSeverity('high')">High</button>
        <button class="tab-btn" onclick="showSeverity('medium')">Medium</button>
        <button class="tab-btn" onclick="showSeverity('low')">Low</button>
    </div>

    <div id="findings-container">
        {findings_html}
    </div>

    <script type="application/json" id="raw-data">{raw_json}</script>

    <script>
        const ctx = document.getElementById('riskChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{critical}, {high}, {medium}, {low}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom' }} }}
            }}
        }});

        function showSeverity(sev) {{
            document.querySelectorAll('.severity-section').forEach(el => {{
                el.classList.add('hidden');
            }});
            const target = document.getElementById('section-' + sev);
            if (target) target.classList.remove('hidden');
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
        }}
        
        function showAll() {{
            document.querySelectorAll('.severity-section').forEach(el => {{
                el.classList.remove('hidden');
            }});
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>"""

def generate_finding_html(finding):
    risk = finding["risk"].lower()
    host = finding["host"]
    sources = finding.get("sources", [])
    confidence = finding.get("confidence_label", "")
    waf = finding.get("waf")
    tls = finding.get("tls_summary", {})

    meta_parts = []
    if sources:
        meta_parts.append(f"Sources: {', '.join(sources)}")
    if confidence:
        meta_parts.append(f"Confidence: {confidence}")
    if waf:
        meta_parts.append(f"WAF: {waf}")

    meta = " | ".join(meta_parts) if meta_parts else ""
    reasons_html = "".join([f'<span class="reason-tag">{r}</span>' for r in finding.get("reasons", [])])

    tls_html = ""
    if tls:
        expired = tls.get("expired", False)
        tls_html = (f'<div style="font-size:0.8rem;color:var(--muted);margin-top:4px;">'
                    f'TLS: {tls.get("version","?").upper()} | Expires: {str(tls.get("not_after","?"))[:10]} '
                    f'{"⚠ EXPIRED" if expired else ""}</div>')

    ip = ", ".join(finding.get("ip", [])) or "unknown"
    cname = ", ".join(finding.get("cname", [])) or "none"
    status = finding.get("status", "unknown")
    server = finding.get("webserver", "unknown")

    return f"""
    <div class="host-row severity-{risk}">
        <div class="host-name"><span class="badge {risk}">{finding["risk"]}</span> {host}</div>
        <div class="host-meta">{meta}</div>
        <div style="font-size:0.85rem;color:var(--muted);">
            IP: {ip} | CNAME: {cname} | Status: {status} | Server: {server}
        </div>
        {tls_html}
        <div class="reasons">{reasons_html}</div>
    </div>
    """

def generate_section_html(title, findings, severity):
    if not findings:
        return ""
    items_html = "".join([generate_finding_html(f) for f in findings])
    return f"""
    <div id="section-{severity}" class="severity-section">
        <div class="section-title" style="color: var(--{severity});">{title} ({len(findings)})</div>
        <div class="card {severity}">
            {items_html}
        </div>
    </div>
    """

def generate_html_report(report, output_path):
    meta = report["meta"]
    summary = report["summary"]
    domain = meta.get("domain", "unknown")

    findings_html = ""
    findings_html += generate_section_html("💀 Critical", report.get("critical", []), "critical")
    findings_html += generate_section_html("🔴 High", report.get("high", []), "high")
    findings_html += generate_section_html("🟡 Medium", report.get("medium", []), "medium")
    findings_html += generate_section_html("🟢 Low", report.get("low", []), "low")

    html = HTML_TEMPLATE.format(
        domain=domain,
        generated_at=meta.get("generated_at", ""),
        tool=meta.get("tool", "ASRCE"),
        total=summary["total"],
        critical=summary["critical"],
        high=summary["high"],
        medium=summary["medium"],
        low=summary["low"],
        findings_html=findings_html,
        raw_json=json.dumps(report)
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)