<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * { font-family: Arial, Helvetica, sans-serif; }
      h1, h2 { text-align: center; }
      .image-section { margin-bottom: 50px; border-bottom: 2px solid #333; padding-bottom: 20px; }
      table { margin: 0 auto; border-collapse: collapse; min-width: 90%; }
      th, td { border: 1px solid black; padding: .5em; text-align: left; }
      .severity-HIGH { background-color: #ff8800; color: white; }
      .severity-CRITICAL { background-color: #e40000; color: white; }
    </style>
    <title>Consolidated Scan Report</title>
  </head>
  <body>
    <h1>Global Security Overview</h1>
    {{- range . }} 
      <div class="image-section">
        <h2>Image: {{ .ArtifactName }}</h2>
        {{- range .Results }}
          <h3>Target: {{ .Target }} ({{ .Type }})</h3>
          {{- if not .Vulnerabilities }}
            <p style="text-align:center;">No vulnerabilities found.</p>
          {{- else }}
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Score</th>
                  <th>Fixed Version</th>
                </tr>
              </thead>
              <tbody>
                {{- range .Vulnerabilities }}
                <tr>
                  <td>{{ .PkgName }}</td>
                  <td>{{ .VulnerabilityID }}</td>
                  <td class="severity-{{ .Severity }}">{{ .Severity }}</td>
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
          {{- end }}
        {{- end }}
      </div>
    {{- end }}
  </body>
</html>