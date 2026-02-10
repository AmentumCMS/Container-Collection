<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * { font-family: Arial, Helvetica, sans-serif; }
      h1 { text-align: center; }
      .group-header th { font-size: 180%; background-color: #f2f2f2; padding: 10px; }
      .sub-header th { font-size: 120%; background-color: #e6e6e6; }
      table, th, td { border: 1px solid black; border-collapse: collapse; white-space: nowrap; padding: .3em; }
      table { margin: 20px auto; min-width: 80%; }
      .severity { text-align: center; font-weight: bold; color: #fafafa; }
      .severity-LOW .severity { background-color: #5fbb31; }
      .severity-MEDIUM .severity { background-color: #e9c600; }
      .severity-HIGH .severity { background-color: #ff8800; }
      .severity-CRITICAL .severity { background-color: #e40000; }
      .severity-UNKNOWN .severity { background-color: #747474; }
      .severity-LOW { background-color: #5fbb3160; }
      .severity-MEDIUM { background-color: #e9c60060; }
      .severity-HIGH { background-color: #ff880060; }
      .severity-CRITICAL { background-color: #e4000060; }
      .severity-UNKNOWN { background-color: #74747460; }
      table tr td:first-of-type { font-weight: bold; }
      .links a { display: block; font-size: 0.8em; }
    </style>
    <title>Global Security Report - {{ now }}</title>
  </head>
  <body>
    <h1>Consolidated Security Overview</h1>
    <p style="text-align: center;">Generated on: {{ now }}</p>
    
    {{- if .Results }}
    <table>
    {{- range .Results }}
      <tr class="group-header">
        <th colspan="6">IMAGE / TARGET: {{ .Target | escapeXML }} ({{ .Type | escapeXML }})</th>
      </tr>
      {{- if (eq (len .Vulnerabilities) 0) }}
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Score</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
      </tr>
      {{- range .Vulnerabilities }}
      <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
        <td>{{ escapeXML .PkgName }}</td>
        <td>{{ escapeXML .VulnerabilityID }}</td>
        <td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
        <td style="text-align:center;">
            {{- $score := 0.0 -}}
            {{- range $source, $cvss := .CVSS -}}
              {{- if $cvss.V3Score -}}{{- $score = $cvss.V3Score -}}{{- end -}}
            {{- end -}}
            {{ printf "%.1f" $score }}
        </td>
        <td>{{ escapeXML .InstalledVersion }}</td>
        <td>{{ escapeXML .FixedVersion }}</td>
      </tr>
      {{- end }}
      {{- end }}
      <tr style="height: 20px;"><td colspan="6" style="border:none;"></td></tr>
    {{- end }}
    </table>
    {{- else }}
    <h1>No Results Found</h1>
    {{- end }}
  </body>
</html>