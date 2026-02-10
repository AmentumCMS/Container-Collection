import json
from jinja2 import Template
from datetime import datetime

def get_cvss_data(v):
    # Returns both score and vector string
    cvss = v.get('CVSS', {})
    for source, data in cvss.items():
        if isinstance(data, dict):
            score = data.get('V3Score')
            vector = data.get('V3Vector')
            if score and vector:
                return score, vector
    return 0.0, "N/A"

def generate(reports):
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <style>
            * { font-family: Arial, Helvetica, sans-serif; }
            h1 { text-align: center; }
            .group-header th { font-size: 160%; background-color: #333; color: white; padding: 10px; }
            .sub-header th { font-size: 110%; background-color: #eee; }
            table { border: 1px solid black; border-collapse: collapse; width: 100%; table-layout: auto; margin-bottom: 30px;}
            th, td { border: 1px solid black; padding: .4em; font-size: 0.9em; }
            .severity { text-align: center; font-weight: bold; color: #fafafa; }
            .severity-LOW { background-color: #5fbb31; }
            .severity-MEDIUM { background-color: #e9c600; }
            .severity-HIGH { background-color: #ff8800; }
            .severity-CRITICAL { background-color: #e40000; }
            .vector-text { font-family: monospace; font-size: 0.8em; color: #555; white-space: normal; word-break: break-all; }
            .links a { display: block; font-size: 0.8em; color: #0056b3; }
        </style>
        <title>Security Consolidated Report</title>
    </head>
    <body>
        <h1>Consolidated Vulnerability Overview</h1>
        <p style="text-align:center">Generated: {{ now }}</p>

        {% for report in reports %}
        <div class="image-section">
            <h2 style="background: #e1e4e8; padding: 10px;">IMAGE: {{ report.ArtifactName }}</h2>
            {% for result in report.Results %}
            <table>
                <tr class="group-header"><th colspan="8">{{ result.Target }} ({{ result.Type }})</th></tr>
                {% if not result.Vulnerabilities %}
                <tr><td colspan="8" style="text-align:center;">No vulnerabilities found</td></tr>
                {% else %}
                <tr class="sub-header">
                    <th>Package</th>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th style="width: 200px;">CVSS Vector</th>
                    <th>Installed</th>
                    <th>Fixed</th>
                    <th>Links</th>
                </tr>
                {% for v in result.Vulnerabilities %}
                {% set score, vector = get_data(v) %}
                <tr>
                    <td><strong>{{ v.PkgName }}</strong></td>
                    <td><a href="https://avd.aquasec.com/nvd/{{ v.VulnerabilityID }}">{{ v.VulnerabilityID }}</a></td>
                    <td class="severity severity-{{ v.Severity }}">{{ v.Severity }}</td>
                    <td style="text-align:center">{{ score }}</td>
                    <td class="vector-text">{{ vector }}</td>
                    <td>{{ v.InstalledVersion }}</td>
                    <td>{{ v.FixedVersion or 'N/A' }}</td>
                    <td class="links">
                        {% for ref in v.References[:3] %}
                        <a href="{{ ref }}">Link</a>
                        {% endfor %}
                    </td>
                </tr>
                {% endfor %}
                {% endif %}
            </table>
            {% endfor %}
        </div>
        {% endfor %}
    </body>
    </html>
    """

    tm = Template(template_str)
    output = tm.render(
        reports=reports, 
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        get_data=get_cvss_data
    )

    with open('combined-reports/overview.html', 'w') as f:
        f.write(output)

if __name__ == "__main__":
    with open('merged_results.json', 'r') as f:
        reports = json.load(f)
        generate(reports)