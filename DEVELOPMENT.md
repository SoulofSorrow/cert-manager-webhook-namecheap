# Development Guide

## Local Setup

```bash
git clone https://github.com/yourusername/cert-manager-webhook-namecheap
cd cert-manager-webhook-namecheap
go mod download
```

## Running Tests

Die Tests verwenden ausschließlich stdlib und lokale httptest-Server —
kein echter Namecheap API-Zugang nötig:

```bash
go test ./pkg/namecheap/ -v
go test ./pkg/solver/ -v
go test ./pkg/dryrun/ -v
go test ./... -v
```

## Local Build

```bash
make build
# Binary landet in bin/webhook
```

## Docker Build

```bash
make docker-build IMAGE=cert-manager-webhook-namecheap TAG=dev
make docker-buildx IMAGE=ghcr.io/yourusername/cert-manager-webhook-namecheap TAG=dev
```

---

## Deployment in K3s

### 1. Egress-IP ermitteln und whitelisten

```bash
kubectl run egress-check --rm -it --image=alpine --restart=Never -- \
  wget -qO- https://api.ipify.org && echo
```

IP eintragen unter: namecheap.com -> Profile -> Tools -> API Access -> Whitelist IPs

### 2. groupName anpassen

```bash
find deploy/ helm/ cmd/ -type f | \
  xargs sed -i 's/acme\.yourdomain\.com/acme.groot.rocks/g'
```

### 3. Credentials anlegen

```bash
kubectl create secret generic namecheap-credentials \
  --namespace cert-manager \
  --from-literal=apiUser=DEIN_USER \
  --from-literal=apiKey=DEIN_API_KEY \
  --from-literal=username=DEIN_USER
```

### 4. Webhook deployen

```bash
kubectl apply -f deploy/rbac/rbac.yaml
kubectl apply -f deploy/apiservice.yaml
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/clusterissuer.yaml
```

### 5. APIService-Status prüfen

```bash
kubectl get apiservice v1alpha1.acme.groot.rocks
# Warten bis: Available=True
```

---

## Dry Run — Webhook-Konfiguration prüfen

Prüft Namecheap-Konfiguration ohne DNS-Records zu schreiben oder
Let's Encrypt zu kontaktieren.

```bash
kubectl port-forward -n cert-manager \
  svc/cert-manager-webhook-namecheap 8080:8080

# Text-Output
curl "http://localhost:8080/dryrun?domain=groot.rocks"

# JSON-Output
curl "http://localhost:8080/dryrun?domain=groot.rocks&format=json"
```

Was geprüft wird:

| Check | Bedeutung |
|---|---|
| Egress IP resolution | Pod kann seine öffentliche IP ermitteln |
| API credentials | Namecheap API erreichbar, Credentials gültig, IP whitelisted |
| DNS record simulation | Merge/Filter-Logik korrekt, kein echter Write |
| CAA record status | CAA Records vorhanden und Let's Encrypt autorisiert |

Beispiel-Output:

```
dry run for domain: groot.rocks
------------------------------------------------
[ok]   egress IP resolution (45ms)
       resolved: 1.2.3.4
[ok]   API credentials (312ms)
       API reachable, credentials valid, 8 existing records found
[ok]   DNS record simulation (0ms)
       add/remove simulation passed (no writes performed), base record count: 8
[fail] CAA record status (0ms)
       letsencrypt.org has issue but not issuewild - wildcard certs will fail
------------------------------------------------
result: one or more checks failed
```

---

## Staging-Test — echter End-to-End Test mit Let's Encrypt

Immer zuerst mit Staging testen. Staging-Zertifikate sind nicht vertrauenswürdig,
aber der komplette Ablauf (DNS-01 Challenge, TXT-Record, Webhook, Namecheap API)
wird identisch durchlaufen.

Vorteile von Staging gegenüber Production:
- Keine Rate Limits (Production: max 5 Zertifikate/Woche pro Domain)
- Fehler ohne Konsequenzen beheben
- Gesamten Ablauf verifizieren bevor Production genutzt wird

### Staging-Zertifikat beantragen

```bash
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: groot-rocks-staging-test
  namespace: default
spec:
  secretName: groot-rocks-staging-tls
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  dnsNames:
    - "groot.rocks"
    - "*.groot.rocks"
EOF
```

### Ablauf beobachten

```bash
# Certificate-Status (Ziel: Ready=True)
kubectl get certificate groot-rocks-staging-test -n default -w

# Detailansicht mit Events
kubectl describe certificate groot-rocks-staging-test -n default

# ACME Challenge live beobachten
kubectl get challenges -A -w

# Webhook-Logs parallel mitverfolgen
kubectl logs -n cert-manager \
  -l app=cert-manager-webhook-namecheap -f
```

### TXT-Record manuell verifizieren

Waehrend die Challenge laeuft pruefen ob der TXT-Record gesetzt wurde:

```bash
dig TXT _acme-challenge.groot.rocks @8.8.8.8
dig TXT _acme-challenge.groot.rocks @1.1.1.1
```

Der Record muss sichtbar sein bevor Let's Encrypt die Challenge als
erfuellt markiert. Propagation dauert 30 Sekunden bis mehrere Minuten.

### Staging erfolgreich — auf Production wechseln

```bash
# Staging aufraumen
kubectl delete certificate groot-rocks-staging-test -n default
kubectl delete secret groot-rocks-staging-tls -n default

# Production-Zertifikat beantragen
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: groot-rocks-wildcard
  namespace: cert-manager
spec:
  secretName: groot-rocks-wildcard-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - "groot.rocks"
    - "*.groot.rocks"
EOF
```

### Per Helm (empfohlen)

```bash
# Erst Staging testen
helm upgrade cert-manager-webhook-namecheap \
  ./helm/cert-manager-webhook-namecheap \
  --namespace cert-manager \
  --set clusterIssuers.enabled=true \
  --set clusterIssuers.email=deine@email.de \
  --set clusterIssuers.staging=true \
  --set 'clusterIssuers.wildcards[0].domain=groot.rocks' \
  --set 'clusterIssuers.wildcards[0].secretName=groot-rocks-wildcard-tls'

# Nach erfolgreichem Staging auf Production wechseln
helm upgrade cert-manager-webhook-namecheap \
  ./helm/cert-manager-webhook-namecheap \
  --namespace cert-manager \
  --set clusterIssuers.staging=false
```

---

## Debugging

```bash
# Webhook-Logs
kubectl logs -n cert-manager -l app=cert-manager-webhook-namecheap -f

# APIService-Status
kubectl get apiservice v1alpha1.acme.groot.rocks
kubectl describe apiservice v1alpha1.acme.groot.rocks

# Certificate-Status
kubectl describe certificate <name> -n <namespace>

# Challenge-Status
kubectl get challenges -A
kubectl describe challenge <name> -n <namespace>

# Dry Run
kubectl port-forward -n cert-manager \
  svc/cert-manager-webhook-namecheap 8080:8080
curl "http://localhost:8080/dryrun?domain=groot.rocks"
```

---

## Haeufige Fehler

**IP nicht in Namecheap Whitelist**
Der Webhook ermittelt seine Egress-IP automatisch, sie muss aber einmalig
manuell in Namecheap eingetragen werden.

**APIService nicht Available**
TLS-Zertifikat des Webhooks noch nicht ausgestellt. Kurz warten, dann
Webhook-Logs pruefen.

**Challenge haengt in pending**
Haeufigste Ursache: DNS-Propagation. TXT-Record mit dig pruefen.
Wenn Record fehlt: Webhook-Logs und Namecheap API-Zugang pruefen.

**Wildcard schlaegt fehl, normales Zertifikat funktioniert**
CAA-Record mit issuewild-Tag fehlt. Dry Run zeigt das Problem.
Webhook setzt Records beim naechsten Present-Aufruf automatisch.

**Namecheap API nicht freigeschaltet**
namecheap.com -> Profile -> Tools -> API Access -> Enable API.
Bei neuen Accounts ggf. Namecheap-Support kontaktieren.

---

## groupName Referenz

| Datei | Stelle |
|---|---|
| cmd/webhook/main.go | GroupName default |
| deploy/deployment.yaml | GROUP_NAME env var |
| deploy/rbac/rbac.yaml | ClusterRole apiGroups |
| deploy/apiservice.yaml | APIService name + spec.group |
| deploy/clusterissuer.yaml | webhook.groupName |
| helm/values.yaml | groupName |
