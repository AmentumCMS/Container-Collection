{{- if . -}}
{{- range . }}
{{- if (gt (len .Vulnerabilities) 0) }}
TARGET: {{ .Target }} ({{ .Type }})
┌────────────────┬──────────────────────┬──────────┬───────────────────┬───────────────────┐
│ Package        │ Vulnerability ID     │ Severity │ Installed Version │ Fixed Version     │
├────────────────┼──────────────────────┼──────────┼───────────────────┼───────────────────┤
{{- range .Vulnerabilities }}
│ {{ printf "%-14.14s" .PkgName }} │ {{ printf "%-20s" .VulnerabilityID }} │ {{ printf "%-8s" .Vulnerability.Severity }} │ {{ printf "%-17.17s" .InstalledVersion }} │ {{ printf "%-17.17s" (default "N/A" .FixedVersion) }} │
{{- end }}
└────────────────┴──────────────────────┴──────────┴───────────────────┴───────────────────┘
{{- end }}
{{- end }}
{{- else }}
Trivy Returned Empty Report
{{- end }}