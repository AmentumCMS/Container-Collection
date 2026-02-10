{{- if .Results -}}
GLOBAL SECURITY COMPLIANCE REPORT
Generated: {{ now }}
{{ range .Results -}}
{{ if (gt (len .Vulnerabilities) 0) -}}
TARGET: {{ .Target }} ({{ .Type }})
+--------------+----------------------+----------+-------+----------------------+----------------------+
| Package      | Vulnerability ID     | Severity | Score | Installed Version    | Fixed Version        |
+--------------+----------------------+----------+-------+----------------------+----------------------+
{{- range .Vulnerabilities }}
| {{ printf "%-12.12s" .PkgName }} | {{ printf "%-20.20s" .VulnerabilityID }} | {{ printf "%-8.8s" .Vulnerability.Severity }} | {{- $score := 0.0 -}}{{- range $source, $cvss := .CVSS -}}{{- if $cvss.V3Score -}}{{- $score = $cvss.V3Score -}}{{- end -}}{{- end -}}{{ printf "%-5.1f" $score }} | {{ printf "%-20.20s" .InstalledVersion }} | {{ printf "%-20.20s" (default "N/A" .FixedVersion) }} |
{{- end }}
+--------------+----------------------+----------+-------+----------------------+----------------------+
{{ end }}
{{- end }}
{{- else -}}
No Vulnerabilities Detected in Merged Report
{{- end -}}