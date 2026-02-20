import json
from jinja2 import Template
from datetime import datetime

def get_cvss_data(v):
    # Returns both score and vector string (best available V3Score/V3Vector)
    cvss = v.get('CVSS', {}) or {}
    best_score = 0.0
    best_vector = "N/A"

    for _, data in cvss.items():
        if isinstance(data, dict):
            score = data.get('V3Score')
            vector = data.get('V3Vector')
            if score is None or vector is None:
                continue
            try:
                fscore = float(score)
            except Exception:
                continue
            # Pick the highest score we find
            if fscore >= best_score:
                best_score = fscore
                best_vector = vector

    return best_score, best_vector

def generate(reports):
    template_str = r"""
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
            th, td { border: 1px solid black; padding: .4em; font-size: 0.9em; vertical-align: top; }

            /* Severity cell */
            .severity { text-align: center; font-weight: bold; color: #fafafa; }
            .severity-LOW .severity { background-color: #5fbb31; }
            .severity-MEDIUM .severity { background-color: #e9c600; color: #333; }
            .severity-HIGH .severity { background-color: #ff8800; }
            .severity-CRITICAL .severity { background-color: #e40000; }
            .severity-UNKNOWN .severity { background-color: #747474; }

            /* Row shading (like Trivy's tpl) */
            tr.severity-LOW { background-color: #5fbb3160; }
            tr.severity-MEDIUM { background-color: #e9c60060; }
            tr.severity-HIGH { background-color: #ff880060; }
            tr.severity-CRITICAL { background-color: #e4000060; }
            tr.severity-UNKNOWN { background-color: #74747460; }

            .vector-text { font-family: monospace; font-size: 0.8em; color: #555; white-space: normal; word-break: break-all; }

            .links a { display: block; font-size: 0.8em; color: #0056b3; }
            .links a.ref-link { display: block; }

            /* SHOW/HIDE LINKS (matches Trivy tpl behavior) */
            td.links[data-more-links="off"] a.ref-link:nth-of-type(n+4) { display: none; }
            a.toggle-more-links { cursor: pointer; font-size: 0.8em; color: #0056b3; }
        </style>

        <title>Security Consolidated Report</title>

        <script>
          window.onload = function() {
            // Hook toggles
            document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
              toggleLink.onclick = function() {
                var parent = toggleLink.parentElement;
                var expanded = parent.getAttribute("data-more-links");
                parent.setAttribute("data-more-links", expanded === "on" ? "off" : "on");
                return false;
              };
            });
          };
        </script>
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
                {% set sev = (v.Severity or 'UNKNOWN') %}
                <tr class="severity-{{ sev }}">
                    <td><strong>{{ v.PkgName }}</strong></td>
                    <td>
                      <a href="https://www.cve.org/CVERecord?id={{ v.VulnerabilityID }}">{{ v.VulnerabilityID }}</a>
                    </td>
                    <td class="severity">{{ sev }}</td>
                    <td style="text-align:center">{{ "%.1f"|format(score) if score else "N/A" }}</td>
                    <td class="vector-text">{{ vector }}</td>
                    <td>{{ v.InstalledVersion }}</td>
                    <td>{{ v.FixedVersion or 'N/A' }}</td>

                    <!-- Links cell with show/hide toggle -->
                    <td class="links" data-more-links="off">
                        {% for ref in (v.References or []) %}
                            <a class="ref-link" href="{{ ref }}">{{ ref }}</a>
                        {% endfor %}
                        {% if v.References and (v.References|length > 3) %}
                            <a href="#toggleMore" class="toggle-more-links">Toggle more links</a>
                        {% endif %}
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

    with open('combined-reports/overview.html', 'w', encoding='utf-8') as f:
        f.write(output)

if __name__ == "__main__":
    with open('merged_results.json', 'r', encoding='utf-8') as f:
        reports = json.load(f)
    generate(reports)