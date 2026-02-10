<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.6; color: #24292e; max-width: 1200px; margin: 0 auto; padding: 20px; }
      h1 { text-align: center; border-bottom: 2px solid #eaecef; padding-bottom: 0.3em; }
      .image-container { margin-top: 40px; border: 1px solid #e1e4e8; border-radius: 6px; padding: 15px; background: #fff; }
      .image-header { background: #f6f8fa; padding: 10px; margin: -15px -15px 15px -15px; border-bottom: 1px solid #e1e4e8; border-radius: 6px 6px 0 0; font-weight: bold; font-size: 1.2em; }
      table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
      th, td { padding: 8px 12px; border: 1px solid #dfe2e5; text-align: left; }
      th { background-color: #f6f8fa; }
      .sev { font-weight: bold; text-align: center; border-radius: 3px; }
      .sev-CRITICAL { background: #cf222e; color: #fff; }
      .sev-HIGH { background: #bc4c00; color: #fff; }
    </style>
    <title>Consolidated Scan Report</title>
  </head>
  <body>
    <h1>Global Security Overview</h1>
    {{- range . }}
    <div class="image-container">
      <div class="image-header">IMAGE: {{ .ArtifactName }}</div>
      {{- range .Results }}
        <h3>Target: {{ .Target }}</h3>
        {{- if .Vulnerabilities }}
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Fixed Version</th>
            </tr>
          </thead>
          <tbody>
            {{- range .Vulnerabilities }}
            <tr>
              <td>{{ .PkgName }}</td>
              <td><a href="https://avd.aquasec.com/nvd/{{ .VulnerabilityID }}">{{ .VulnerabilityID }}</a></td>
              <td class="sev sev-{{ .Severity }}">{{ .Severity }}</td>
              <td>
                {{- $score := 0.0 -}}
                {{- range $source, $cvss := .CVSS -}}
                  {{- if $cvss.V3Score -}}{{- $score = $cvss.V3Score -}}{{- end -}}
                {{- end -}}
                {{ printf "%.1f" $score }}
              </td>
              <td>{{ default "N/A" .FixedVersion }}</td>
            </tr>
            {{- end }}
          </tbody>
        </table>
        {{- else }}
        <p>No vulnerabilities found for this target.</p>
        {{- end }}
      {{- end }}
    </div>
    {{- end }}
  </body>
</html>