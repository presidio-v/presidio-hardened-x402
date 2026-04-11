{{/*
Expand the name of the chart.
*/}}
{{- define "presidio-hardened-x402.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "presidio-hardened-x402.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "presidio-hardened-x402.labels" -}}
helm.sh/chart: {{ include "presidio-hardened-x402.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "presidio-hardened-x402.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "presidio-hardened-x402.selectorLabels" -}}
app.kubernetes.io/name: {{ include "presidio-hardened-x402.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
