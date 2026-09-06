{{/*
Nom court du chart, utilisé comme préfixe par défaut.
*/}}
{{- define "open-eidas.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Nom complet de la release, préfixé par le nom du chart sauf s'il y figure déjà.
*/}}
{{- define "open-eidas.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "open-eidas.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels communs à toutes les ressources.
*/}}
{{- define "open-eidas.labels" -}}
helm.sh/chart: {{ include "open-eidas.chart" . }}
{{ include "open-eidas.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "open-eidas.selectorLabels" -}}
app.kubernetes.io/name: {{ include "open-eidas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Labels/nom d'un composant particulier (tsa, openxpki, mariadb, audit-replica).
*/}}
{{- define "open-eidas.componentName" -}}
{{- printf "%s-%s" (include "open-eidas.fullname" .context) .component -}}
{{- end -}}

{{- define "open-eidas.componentSelectorLabels" -}}
{{ include "open-eidas.selectorLabels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "open-eidas.componentLabels" -}}
{{ include "open-eidas.labels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Nom du Secret contenant les valeurs générées automatiquement (mots de passe,
PIN, clé du coffre de données) et stables d'un `helm upgrade` à l'autre.
*/}}
{{- define "open-eidas.generatedSecretName" -}}
{{- printf "%s-generated" (include "open-eidas.fullname" .) -}}
{{- end -}}
