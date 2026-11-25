{{/*
The value combinations that the chart refuses to render. deployment.yaml includes this
template, so every render runs it.
*/}}
{{- define "hst.validate" -}}
{{- $analysis := index .Values.analysis.profiles .Values.analysis.profile -}}
{{- if and (eq (default "unknown" $analysis.clockQuality) "trusted") (not $analysis.clockAssumption) -}}
{{- fail "analysis.profiles.<profile>.clockQuality=trusted requires clockAssumption: the statement of the basis for trusting the collector host clock." -}}
{{- end -}}
{{- if and (ne (default "unknown" $analysis.clockQuality) "trusted") $analysis.clockAssumption -}}
{{- fail "analysis.profiles.<profile>.clockAssumption requires clockQuality=trusted." -}}
{{- end -}}
{{- if and (eq (default "bounded-window" $analysis.evidenceConsistency) "stable-window-assumption") (not $analysis.evidenceStableWindowAssumption) -}}
{{- fail "analysis.profiles.<profile>.evidenceConsistency=stable-window-assumption requires evidenceStableWindowAssumption: the statement that the estate did not change within the evidence window." -}}
{{- end -}}
{{- if and (ne (default "bounded-window" $analysis.evidenceConsistency) "stable-window-assumption") $analysis.evidenceStableWindowAssumption -}}
{{- fail "analysis.profiles.<profile>.evidenceStableWindowAssumption requires evidenceConsistency=stable-window-assumption." -}}
{{- end -}}
{{- if and .Values.backup.enabled (not .Values.postgres.enabled) -}}
{{- fail "backup.enabled=true requires postgres.enabled=true: the recovery-set job must produce and verify its own identity-store dump." -}}
{{- end -}}
{{- if and .Values.backup.enabled (not .Values.app.persistence.enabled) -}}
{{- fail "backup.enabled=true requires app.persistence.enabled=true: graph archives and wrapped keys must be staged from the data PVC." -}}
{{- end -}}
{{- if and .Values.worker.enabled (not .Values.app.persistence.enabled) -}}
{{- fail "worker.enabled=true requires app.persistence.enabled=true: the worker writes the raw store, the side store and the progress records the app reads, and an emptyDir is not shared between pods." -}}
{{- end -}}
{{- if and .Values.worker.enabled (eq .Values.app.persistence.accessMode "ReadWriteOncePod") -}}
{{- fail "worker.enabled=true cannot share a ReadWriteOncePod data volume: the app pod and the worker pod both mount it. ReadWriteOnce places the worker on the app pod's node; ReadWriteMany places it on any node." -}}
{{- end -}}
{{- if and (include "hst.forwardedAllowIps" .) (not (and .Values.networkPolicy.enabled .Values.networkPolicy.ingressFrom)) -}}
{{- fail "app.forwardedAllowIps needs networkPolicy.enabled=true and a peer in networkPolicy.ingressFrom. Without them any pod in the cluster can send X-Forwarded-For to port 8787 of the app pod. Set networkPolicy.ingressFrom to the pods of the ingress controller, or set app.forwardedAllowIps to \"\" to trust no proxy." -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.tls.enabled) (not .Values.ingress.acceptInsecureHttp) -}}
{{- fail "ingress.enabled=true with ingress.tls.enabled=false serves admin login and the session cookie over plaintext HTTP, on a system that stores network-device credentials. Terminate TLS (ingress.tls.enabled=true with ingress.tls.secretName), or, if TLS terminates upstream or this is local dev, accept the risk explicitly with ingress.acceptInsecureHttp=true." -}}
{{- end -}}
{{- if and .Values.ingress.tls.enabled (not .Values.auth.cookieSecure) -}}
{{- fail "ingress.tls.enabled=true but auth.cookieSecure=false: the session cookie would not be marked Secure. Set auth.cookieSecure=true so it matches the TLS front." -}}
{{- end -}}
{{- if and .Values.auth.cookieSecure (not .Values.ingress.tls.enabled) (not .Values.ingress.acceptInsecureHttp) -}}
{{- fail "auth.cookieSecure=true but no TLS in front (ingress.tls.enabled=false): a browser refuses to send a Secure cookie over plain HTTP, so login fails. Enable ingress.tls.enabled, or set ingress.acceptInsecureHttp=true if TLS terminates upstream." -}}
{{- end -}}
{{- if and .Values.neo4j.tls.enabled (not .Values.neo4j.tls.caSecret) -}}
{{- fail "neo4j.tls.enabled=true requires neo4j.tls.caSecret: the name of a Secret in this namespace holding the CA certificate under the key ca.crt." -}}
{{- end -}}
{{- if and .Values.postgres.tls.enabled (not .Values.postgres.tls.caSecret) -}}
{{- fail "postgres.tls.enabled=true requires postgres.tls.caSecret: the name of a Secret in this namespace holding the CA certificate under the key ca.crt." -}}
{{- end -}}
{{- if and .Values.neo4j.tls.serverSecret (not .Values.neo4j.enabled) -}}
{{- fail "neo4j.tls.serverSecret is the TLS listener of the bundled Neo4j, and neo4j.enabled=false: there is no bundled Neo4j to give it to." -}}
{{- end -}}
{{- if and .Values.neo4j.tls.serverSecret (not .Values.neo4j.tls.enabled) -}}
{{- fail "neo4j.tls.serverSecret makes the bundled Neo4j require TLS on bolt, and neo4j.tls.enabled=false leaves the app dialing it in the clear. Set neo4j.tls.enabled=true with neo4j.tls.caSecret holding the CA of the server certificate." -}}
{{- end -}}
{{- if and .Values.postgres.tls.serverSecret (not .Values.postgres.enabled) -}}
{{- fail "postgres.tls.serverSecret is the TLS listener of the bundled Postgres, and postgres.enabled=false: there is no bundled Postgres to give it to." -}}
{{- end -}}
{{- if and .Values.postgres.tls.serverSecret (not .Values.postgres.tls.enabled) -}}
{{- fail "postgres.tls.serverSecret turns on TLS in the bundled Postgres, and postgres.tls.enabled=false leaves the app connecting without verifying it. Set postgres.tls.enabled=true with postgres.tls.caSecret holding the CA of the server certificate." -}}
{{- end -}}
{{- if and .Values.neo4j.externalUri (not .Values.neo4j.tls.enabled) (not .Values.neo4j.acceptInsecure) (eq (include "hst.isLoopbackHost" .Values.neo4j.externalUri) "false") -}}
{{- fail "neo4j.externalUri points at a non-loopback host with neo4j.tls.enabled=false: the bolt session, including the admin password, crosses the network in the clear. Set neo4j.tls.enabled=true (with neo4j.tls.caSecret), or, if this hop is already encrypted or trusted some other way, accept the risk explicitly with neo4j.acceptInsecure=true." -}}
{{- end -}}
{{- if and .Values.postgres.externalDsn (not .Values.postgres.tls.enabled) (not .Values.postgres.acceptInsecure) (eq (include "hst.isLoopbackHost" .Values.postgres.externalDsn) "false") -}}
{{- fail "postgres.externalDsn points at a non-loopback host with postgres.tls.enabled=false: the session, including credentials, crosses the network unverified. Set postgres.tls.enabled=true (with postgres.tls.caSecret), or, if this hop is already encrypted or trusted some other way, accept the risk explicitly with postgres.acceptInsecure=true." -}}
{{- end -}}
{{- if and (not .Values.postgres.enabled) .Values.secrets.existingSecret -}}
{{- if .Values.postgres.externalDsn -}}
{{- fail "postgres.externalDsn must be empty with secrets.existingSecret." -}}
{{- end -}}
{{- if and (not .Values.postgres.tls.enabled) (not .Values.postgres.acceptInsecure) -}}
{{- fail "postgres.enabled=false with secrets.existingSecret requires postgres.tls.enabled=true or postgres.acceptInsecure=true." -}}
{{- end -}}
{{- end -}}
{{- /*
"change-me" is the placeholder of .env.example and of core/config.py. The check runs only
when the chart renders the Secret, because a template cannot read an existingSecret.
*/}}
{{- if not .Values.secrets.existingSecret -}}
{{- if eq .Values.secrets.secretKey "change-me" -}}
{{- fail "secrets.secretKey is the placeholder \"change-me\". Generate a key with `hst secret-key`." -}}
{{- end -}}
{{- if eq .Values.secrets.neo4jPassword "change-me" -}}
{{- fail "secrets.neo4jPassword is the placeholder \"change-me\". Set a password." -}}
{{- end -}}
{{- if eq .Values.secrets.postgresPassword "change-me" -}}
{{- fail "secrets.postgresPassword is the placeholder \"change-me\". Set a password." -}}
{{- end -}}
{{- end -}}
{{- end -}}
