{{/*
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "vso.chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "vso.chart.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "vso.chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vso.chart.labels" -}}
helm.sh/chart: {{ include "vso.chart.chart" . }}
{{ include "vso.chart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vso.chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vso.chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "vso.chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vso.chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
VaultAuthMethod Spec
** Keep this up to date when we make changes to the VaultAuthMethod Spec **
*/}}
{{- define "vso.vaultAuthMethod" -}}
  {{- $cur := index . 0 }}
  {{- $serviceAccount := index . 1 }}
  {{- $root := index . 2 }}
  {{- if eq $cur.method "kubernetes" }}
  kubernetes:
    role: {{ $cur.kubernetes.role }}
    serviceAccount: {{ $serviceAccount }}
    {{- if $cur.kubernetes.tokenAudiences }}
    audiences: {{ $cur.kubernetes.tokenAudiences | toJson }}
    {{- end }}
  {{- else if eq $cur.method "jwt" }}
  jwt:
    role: {{ $cur.jwt.role }}
    {{- if $cur.jwt.secretRef }}
    secretRef: {{ $cur.jwt.secretRef }}
    {{- else if $cur.jwt.serviceAccount }}
    serviceAccount: {{ $cur.jwt.serviceAccount }}
    {{- if $cur.jwt.tokenAudiences }}
    audiences: {{ $cur.jwt.tokenAudiences | toJson }}
    {{- end }}
    {{- end }}
  {{- else if eq $cur.method "appRole" }}
  appRole:
    roleId: {{ $cur.appRole.roleId }}
    secretRef: {{ $cur.appRole.secretRef }}
  {{- end }}
  {{- if $cur.headers }}
  headers:
    {{- toYaml $cur.headers | nindent 8 }}
  {{- end }}
  {{- if $cur.params }}
  params:
    {{- toYaml $cur.params | nindent 8 }}
  {{- else if eq $cur.method "aws" }}
  aws:
    role: {{ $cur.aws.role }}
    {{- if $cur.aws.region }}
    region: {{ $cur.aws.region }}
    {{- end }}
    {{- if $cur.aws.headerValue }}
    headerValue: {{ $cur.aws.headerValue }}
    {{- end }}
    {{- if $cur.aws.sessionName }}
    sessionName: {{ $cur.aws.sessionName }}
    {{- end }}
    {{- if $cur.aws.stsEndpoint }}
    stsEndpoint: {{ $cur.aws.stsEndpoint }}
    {{- end }}
    {{- if $cur.aws.iamEndpoint }}
    iamEndpoint: {{ $cur.aws.iamEndpoint }}
    {{- end }}
    {{- if $cur.aws.secretRef }}
    secretRef: {{ $cur.aws.secretRef }}
    {{- end }}
    {{- if $cur.aws.irsaServiceAccount }}
    irsaServiceAccount: {{ $cur.aws.irsaServiceAccount }}
    {{- end }}
  {{- else if eq $cur.method "gcp" }}
  gcp:
    role: {{ $cur.gcp.role }}
    workloadIdentityServiceAccount: {{ $cur.gcp.workloadIdentityServiceAccount }}
    {{- if $cur.gcp.region }}
    region: {{ $cur.gcp.region }}
    {{- end }}
    {{- if $cur.gcp.clusterName }}
    clusterName: {{ $cur.gcp.clusterName }}
    {{- end }}
    {{- if $cur.gcp.projectID }}
    projectID: {{ $cur.gcp.projectID }}
    {{- end }}
  {{- end }}
{{- end}}

{{/*
imagePullSecrets generates pull secrets from either string or map values.
A map value must be indexable by the key 'name'.
*/}}
{{- define "vso.imagePullSecrets" -}}
{{ with .Values.controller.imagePullSecrets -}}
imagePullSecrets:
{{- range . -}}
{{- if typeIs "string" . }}
 - name: {{ . }}
{{- else if index . "name" }}
 - name: {{ .name }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}


{{/*
globalTransformationOptions configures the manager's --global-transformation-options
*/}}
{{- define "vso.globalTransformationOptions" -}}
{{- $opts := list -}}
{{- if .Values.controller.manager.globalTransformationOptions.excludeRaw }}
{{- $opts = mustAppend $opts "exclude-raw" -}}
{{- end -}}
{{- if $opts -}}
{{- $opts | join "," -}}
{{- end -}}
{{- end -}}
