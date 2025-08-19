from pathlib import Path
import pandas as pd
from jinja2 import Template

TPL = """
<!doctype html><html><head>
<meta charset="utf-8"><title>Mini-SIEM Findings</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css">
</head><body class="p-4">
<h1>Mini-SIEM Findings ({{n}})</h1>
<table class="table table-sm table-bordered">
<thead><tr><th>User</th><th>Reason</th><th>Severity</th><th>When</th><th>Source</th></tr></thead>
<tbody>
{% for r in rows -%}
<tr class="table-{{ 'danger' if r['Severity'] in ['Critical','High'] else 'warning' if r['Severity']=='Medium' else 'light' }}">
<td>{{r['SamAccountName']}}</td><td>{{r['Reason']}}</td><td>{{r['Severity']}}</td><td>{{r['When']}}</td><td>{{r['SourceFile']}}</td>
</tr>
{%- endfor %}
</tbody></table></body></html>
"""

def write_reports(findings: pd.DataFrame, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    findings.to_csv(outdir/"findings.csv", index=False, encoding="utf-8")
    html = Template(TPL).render(rows=findings.to_dict(orient="records"), n=len(findings))
    (outdir/"report.html").write_text(html, encoding="utf-8")
