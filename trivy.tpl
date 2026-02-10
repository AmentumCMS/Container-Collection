{{- if . -}}
{{- range . }}
{{- if (gt (len .Vulnerabilities) 0) }}
TARGET: {{ .Target }} ({{ .Type }})
+--------------+----------------------+----------+-------+----------------------+----------------------+
| Package      | Vulnerability ID     | Severity | Score | Installed Version    | Fixed Version        |
+--------------+----------------------+----------+-------+----------------------+----------------------+
{{- range .Vulnerabilities }}
| {{ printf "%-12.12s" .PkgName }} | {{ printf "%-20.20s" .VulnerabilityID }} | {{ printf "%-8.8s" .Vulnerability.Severity }} | {{ printf "%-5.1f" (index .CVSS "nvd").V3Score | default 0.0 }} | {{ printf "%-20.20s" .InstalledVersion }} | {{ printf "%-20.20s" (default "N/A" .FixedVersion) }} |
{{- end }}
+--------------+----------------------+----------+-------+----------------------+----------------------+
{{- end }}
{{- end }}
{{- else }}
Trivy Returned Empty Report
{{- end }}