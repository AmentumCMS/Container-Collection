{{- range . }}
{{- if .Vulnerabilities }}
IMAGE: {{ $.ArtifactName }}
┌────────────────┬──────────────────────┬──────────┬───────────────────┬───────────────────┐
│ Library        │ Vulnerability ID     │ Severity │ Installed Version │ Fixed Version     │
├────────────────┼──────────────────────┼──────────┼───────────────────┼───────────────────┤
{{- range .Vulnerabilities }}
│ {{ printf "%.14s" .PkgName | printf "%-14s" }} │ {{ printf "%-20s" .VulnerabilityID }} │ {{ printf "%-8s" .Severity }} │ {{ printf "%-17s" .InstalledVersion }} │ {{ printf "%-17s" .FixedVersion }} │
{{- end }}
└────────────────┴──────────────────────┴──────────┴───────────────────┴───────────────────┘
{{- end }}
{{- end }}