{{- define "hst.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hst.fullname" -}}
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

{{- define "hst.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "hst.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "hst.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hst.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "hst.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "hst.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "hst.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "hst.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
The bytes of a Kubernetes memory quantity. The quantity is a number with a binary suffix
(Ki to Ei), a decimal suffix (k to E), a decimal exponent (e9) or no suffix. A quantity in
any other form fails the render.
*/}}
{{- define "hst.memoryBytes" -}}
{{- $quantity := toString . -}}
{{- $numberPattern := "^([0-9]+([.][0-9]*)?|[.][0-9]+)" -}}
{{- if not (regexMatch (printf "%s([eE][+-]?[0-9]+|Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$" $numberPattern) $quantity) -}}
{{- fail (printf "memory limit %q is not a Kubernetes quantity of bytes" $quantity) -}}
{{- end -}}
{{- $number := regexFind $numberPattern $quantity -}}
{{- $suffix := trimPrefix $number $quantity -}}
{{- $scale := dict "" 1.0 "Ki" 1024.0 "Mi" 1048576.0 "Gi" 1073741824.0 "Ti" 1099511627776.0 "Pi" 1125899906842624.0 "Ei" 1152921504606846976.0 "k" 1000.0 "M" 1000000.0 "G" 1000000000.0 "T" 1000000000000.0 "P" 1000000000000000.0 "E" 1000000000000000000.0 -}}
{{- if hasKey $scale $suffix -}}
{{- mulf (float64 $number) (get $scale $suffix) -}}
{{- else -}}
{{- float64 $quantity -}}
{{- end -}}
{{- end -}}

{{/*
image.digest wins over image.tag.
*/}}
{{- define "hst.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
The hostnames of the Ingress as a JSON array, without duplicates.
*/}}
{{- define "hst.ingressHosts" -}}
{{- prepend .Values.ingress.extraHosts .Values.ingress.host | uniq | toJson -}}
{{- end -}}

{{/*
The value of HST_FORWARDED_ALLOW_IPS that the chart sets in the app pod. It is empty
without the ingress, and when app.extraEnv names the variable.
*/}}
{{- define "hst.forwardedAllowIps" -}}
{{- $inExtraEnv := false -}}
{{- range .Values.app.extraEnv -}}
{{- if eq (toString .name) "HST_FORWARDED_ALLOW_IPS" -}}
{{- $inExtraEnv = true -}}
{{- end -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not $inExtraEnv) -}}
{{- .Values.app.forwardedAllowIps -}}
{{- end -}}
{{- end -}}

{{- define "hst.postgresHost" -}}
{{- printf "%s-postgres" (include "hst.fullname" .) -}}
{{- end -}}

{{- define "hst.neo4jHost" -}}
{{- printf "%s-neo4j" (include "hst.fullname" .) -}}
{{- end -}}

{{/*
Kubernetes expands $(POSTGRES_PASSWORD) from the env entry of that name.
*/}}
{{- define "hst.postgresDsnTemplate" -}}
{{- printf "postgresql+asyncpg://%s:$(POSTGRES_PASSWORD)@%s:5432/%s" .Values.postgres.username (include "hst.postgresHost" .) .Values.postgres.database -}}
{{- end -}}

{{- define "hst.neo4jUri" -}}
{{- if .Values.neo4j.enabled -}}
{{- printf "bolt://%s:7687" (include "hst.neo4jHost" .) -}}
{{- else -}}
{{- required "neo4j.enabled is false, so neo4j.externalUri is required" .Values.neo4j.externalUri -}}
{{- end -}}
{{- end -}}

{{/*
The string "true" when the host of a bolt or Postgres URI is localhost, a 127.0.0.0/8
literal or ::1, and the string "false" for any other host.
*/}}
{{- define "hst.isLoopbackHost" -}}
{{- $host := (urlParse .).hostname -}}
{{- if or (eq $host "localhost") (eq $host "::1") (hasPrefix "127." $host) -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
The CA certificates of the Neo4j and Postgres connections. Each comes from the Secret
named in tls.caSecret, under the key `ca.crt`, and is mounted read-only.
*/}}
{{- define "hst.neo4jCaFile" -}}
/etc/hst/tls/neo4j/ca.crt
{{- end -}}

{{- define "hst.postgresCaFile" -}}
/etc/hst/tls/postgres/ca.crt
{{- end -}}

{{- define "hst.neo4jCaVolume" -}}
- name: neo4j-ca
  secret:
    secretName: {{ .Values.neo4j.tls.caSecret }}
    items:
      - key: ca.crt
        path: ca.crt
{{- end -}}

{{- define "hst.neo4jCaVolumeMount" -}}
- name: neo4j-ca
  mountPath: /etc/hst/tls/neo4j
  readOnly: true
{{- end -}}

{{- define "hst.postgresCaVolume" -}}
- name: postgres-ca
  secret:
    secretName: {{ .Values.postgres.tls.caSecret }}
    items:
      - key: ca.crt
        path: ca.crt
{{- end -}}

{{- define "hst.postgresCaVolumeMount" -}}
- name: postgres-ca
  mountPath: /etc/hst/tls/postgres
  readOnly: true
{{- end -}}

{{/*
The environment of the app, the worker, the migration Job, the init-db Job and the
`prepare` container of the backup. Each secret is a secretKeyRef.
*/}}
{{- define "hst.env" -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hst.secretName" . }}
      key: postgres-password
- name: POSTGRES_DSN
{{- if .Values.postgres.enabled }}
  value: {{ include "hst.postgresDsnTemplate" . | quote }}
{{- else }}
  valueFrom:
    secretKeyRef:
      name: {{ include "hst.secretName" . }}
      key: postgres-dsn
{{- end }}
- name: NEO4J_URI
  value: {{ include "hst.neo4jUri" . | quote }}
- name: NEO4J_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hst.secretName" . }}
      key: neo4j-password
{{- if .Values.neo4j.tls.enabled }}
- name: NEO4J_TLS_CA_FILE
  value: {{ include "hst.neo4jCaFile" . | quote }}
{{- end }}
{{- if .Values.postgres.tls.enabled }}
- name: POSTGRES_CA_FILE
  value: {{ include "hst.postgresCaFile" . | quote }}
{{- end }}
{{- /*
The operator key is a file. The app, the worker and the `prepare` container of the backup
mount the Secret at /etc/hst. The migration and init-db containers do not mount it.
*/}}
- name: HST_SECRET_KEY_FILE
  value: /etc/hst/secret-key
{{- /*
The clock declaration and the evidence policy of the analysis profile. A collection run
writes the declaration into the manifest, and the run executes in the app pod or in the
worker pod.
*/}}
{{- $analysis := index .Values.analysis.profiles .Values.analysis.profile }}
- name: COLLECTOR_CLOCK_QUALITY
  value: {{ default "unknown" $analysis.clockQuality | quote }}
- name: COLLECTOR_CLOCK_ASSUMPTION
  value: {{ default "" $analysis.clockAssumption | quote }}
- name: ANALYSIS_EVIDENCE_MAX_AGE_S
  value: {{ (hasKey $analysis "evidenceMaxAgeSeconds" | ternary $analysis.evidenceMaxAgeSeconds 3600) | quote }}
- name: ANALYSIS_EVIDENCE_MAX_SKEW_S
  value: {{ (hasKey $analysis "evidenceMaxSkewSeconds" | ternary $analysis.evidenceMaxSkewSeconds 300) | quote }}
- name: ANALYSIS_EVIDENCE_CONSISTENCY_MODE
  value: {{ default "bounded-window" $analysis.evidenceConsistency | quote }}
- name: ANALYSIS_EVIDENCE_STABLE_WINDOW_ASSUMPTION
  value: {{ default "" $analysis.evidenceStableWindowAssumption | quote }}
- name: HST_DATA_DIR
  value: /srv/data
- name: WEB_DIST
  value: /srv/web/dist
{{- $publicUrl := .Values.app.publicUrl }}
{{- if and (not $publicUrl) .Values.ingress.enabled .Values.ingress.host }}
{{- $publicUrl = printf "%s://%s" (ternary "https" "http" .Values.ingress.tls.enabled) .Values.ingress.host }}
{{- end }}
{{- with $publicUrl }}
- name: HST_PUBLIC_URL
  value: {{ . | quote }}
{{- end }}
{{- /*
The Containerfile sets HST_BUILD_REVISION to the git SHA of the build.
image.buildRevision overrides it.
*/}}
{{- with .Values.image.buildRevision }}
- name: HST_BUILD_REVISION
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/*
The egress rules of a pod of the release. The argument is a dict. `root` is the chart
context. `neo4j` and `postgres` add the rule to the pod of the bundled database. `other`
adds the rule to every address outside networkPolicy.egress.except. The API server
requires each `except` entry to lie inside the `cidr` of its ipBlock, so the entries with
a colon go to ::/0 and the other entries go to 0.0.0.0/0.
*/}}
{{- define "hst.egressRules" -}}
{{- $root := .root -}}
- ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  {{- with $root.Values.networkPolicy.dnsTo }}
  to: {{- toYaml . | nindent 4 }}
  {{- end }}
{{- if .neo4j }}
- to:
    - podSelector:
        matchLabels: {{- include "hst.selectorLabels" $root | nindent 10 }}
          app.kubernetes.io/component: neo4j
  ports:
    - port: 7687
      protocol: TCP
{{- end }}
{{- if .postgres }}
- to:
    - podSelector:
        matchLabels: {{- include "hst.selectorLabels" $root | nindent 10 }}
          app.kubernetes.io/component: postgres
  ports:
    - port: 5432
      protocol: TCP
{{- end }}
{{- if .other }}
{{- $v4 := list -}}
{{- $v6 := list -}}
{{- range $root.Values.networkPolicy.egress.except -}}
{{- if contains ":" . -}}
{{- $v6 = append $v6 . -}}
{{- else -}}
{{- $v4 = append $v4 . -}}
{{- end -}}
{{- end }}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        {{- with $v4 }}
        except: {{- toYaml . | nindent 10 }}
        {{- end }}
    - ipBlock:
        cidr: ::/0
        {{- with $v6 }}
        except: {{- toYaml . | nindent 10 }}
        {{- end }}
{{- end }}
{{- end -}}

{{/*
The init container of the app and worker pods. It ends when the Postgres schema is at the
revision that the image expects.
*/}}
{{- define "hst.waitForMigrations" -}}
- name: wait-for-migrations
  image: {{ include "hst.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command:
    - sh
    - -c
    - |
      n=0
      until hst migrate --check; do
        n=$((n + 1))
        if [ "$n" -ge {{ .Values.migrations.waitAttempts }} ]; then
          echo "migration job has not completed after $n attempts; giving up"
          exit 1
        fi
        echo "waiting for the migration job"; sleep 3
      done
  env: {{- include "hst.env" . | nindent 4 }}
  securityContext:
    runAsNonRoot: true
    runAsUser: {{ .Values.podSecurityContext.runAsUser }}
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities: { drop: ["ALL"] }
  resources: {{- toYaml .Values.migrations.resources | nindent 4 }}
  {{- if .Values.postgres.tls.enabled }}
  volumeMounts:
    {{- include "hst.postgresCaVolumeMount" . | nindent 4 }}
  {{- end }}
{{- end -}}
