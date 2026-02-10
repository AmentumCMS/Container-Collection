{{- range . -}}
================================================================================
IMAGE: {{ .ArtifactName }}
================================================================================
{{ range .Results -}}
{{ if .Vulnerabilities -}}
Target: {{ .Target }} ({{ .Type }})
+--------------+----------------------+----------+-------+----------------------+
| Package      | Vulnerability ID     | Severity | Score | Fixed Version        |
+--------------+----------------------+----------+-------+----------------------+
{{- range .Vulnerabilities }}
| {{ printf "%-12.12s" .PkgName }} | {{ printf "%-20.20s" .VulnerabilityID }} | {{ printf "%-8.8s" .Severity }} | {{- $score := 0.0 -}}{{- range $source, $cvss := .CVSS -}}{{- if $cvss.V3Score -}}{{- $score = $cvss.V3Score -}}{{- end -}}{{- end -}}{{ printf "%-5.1f" $score }} | {{ printf "%-20.20s" (default "N/A" .FixedVersion) }} |
{{- end }}
+--------------+----------------------+----------+-------+----------------------+
{{ end }}
{{- end }}
{{- end }}