{{- range .Results }}
{{- if .Vulnerabilities }}
Target: {{ .Target }}
┌────────────────┬──────────────────────┬──────────┬───────────────────┬───────────────────┐
│ Library        │ Vulnerability ID     │ Severity │ Installed Version │ Fixed Version     │
├────────────────┼──────────────────────┼──────────┼───────────────────┼───────────────────┤
{{- range .Vulnerabilities }}
│ {{ printf "%-14.14s" .PkgName }} │ {{ printf "%-20s" .VulnerabilityID }} │ {{ printf "%-8s" .Severity }} │ {{ printf "%-17.17s" .InstalledVersion }} │ {{ printf "%-17.17s" (default "N/A" .FixedVersion) }} │
{{- end }}
└────────────────┴──────────────────────┴──────────┴───────────────────┴───────────────────┘
{{- end }}
{{- end }}