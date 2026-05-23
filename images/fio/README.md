# FIO — Flexible I/O Tester with HTTP Controller

Minimal container image (scratch-based) shipping [fio](https://github.com/axboe/fio) alongside a Go HTTP controller to drive I/O benchmarks externally.

## Architecture

```
┌─────────────────────────────────────────┐
│  Container (scratch)                    │
│                                         │
│  fio-controller (:8080)                 │
│    │                                    │
│    ├─ POST /start  → launches fio       │
│    ├─ POST /stop   → SIGTERM → graceful │
│    ├─ GET  /status → job state          │
│    ├─ GET  /output → fio results        │
│    └─ GET  /health → liveness probe     │
│                                         │
│  fio (static binary)                    │
└─────────────────────────────────────────┘
```

The controller starts alone and waits for a `/start` call to launch fio. This lets you control the benchmark lifecycle externally without redeploying the pod.

## Build

```bash
docker build -t ghcr.io/evariops/fio:v3.41.0 images/fio/
```

Multi-arch:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/evariops/fio:v3.41.0 --push images/fio/
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/start` | POST | Start fio (optional JSON body) |
| `/stop` | POST | Graceful stop (SIGTERM → full results) |
| `/status` | GET | State: `idle`, `running`, `done` + exit code |
| `/output` | GET | Raw fio output (10 MB ring buffer) |
| `/health` | GET | Liveness probe |

### POST /start

Three launch modes:

**1. Inline job file:**

```bash
curl -X POST http://fio:8080/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "job": "[global]\nioengine=libaio\ndirect=1\nbs=4k\nsize=1G\nruntime=300\ntime_based=1\n\n[randread]\nrw=randread\niodepth=32\n",
    "extra_args": ["--output-format=json+"]
  }'
```

**2. Mounted job file reference (ConfigMap):**

```bash
curl -X POST http://fio:8080/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"args": ["/etc/fio/job.fio", "--output-format=json+"]}'
```

**3. Raw CLI arguments:**

```bash
curl -X POST http://fio:8080/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"args": ["--name=bench", "--ioengine=libaio", "--direct=1", "--bs=4k", "--rw=randread", "--size=1G", "--runtime=60", "--time_based=1", "--output-format=json+"]}'
```

### POST /stop

Sends `SIGTERM` to fio which triggers a graceful shutdown: it completes in-flight I/O, collects statistics, and produces the full result output (including JSON).

```bash
curl -X POST http://fio:8080/stop -H "Authorization: Bearer $TOKEN"
```

### GET /output

Retrieve the result after stopping:

```bash
curl http://fio:8080/output -H "Authorization: Bearer $TOKEN"
```

## Security

| Measure | Detail |
|---------|--------|
| Authentication | Bearer token via `FIO_AUTH_TOKEN` environment variable |
| Directive blocklist | `exec_prerun`, `exec_postrun`, `ioengine=exec` rejected |
| Argument blocklist | `--trigger`, `--trigger-remote` blocked |
| Body limit | 1 MB max on `/start` |
| Scratch image | No shell, no libraries, minimal attack surface |
| Non-root | Runs as UID 1000 |

If `FIO_AUTH_TOKEN` is not set, the API is open — in that case, secure access with a Kubernetes NetworkPolicy.

## Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fio-secret
type: Opaque
stringData:
  token: "your-secure-token-here"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fio-job
data:
  job.fio: |
    [global]
    ioengine=libaio
    direct=1
    bs=4k
    size=1G
    runtime=3600
    time_based=1
    output-format=json+

    [randread]
    rw=randread
    iodepth=32
---
apiVersion: v1
kind: Pod
metadata:
  name: fio-bench
spec:
  containers:
  - name: fio
    image: ghcr.io/evariops/fio:v3.41.0
    ports:
    - containerPort: 8080
    env:
    - name: FIO_AUTH_TOKEN
      valueFrom:
        secretKeyRef:
          name: fio-secret
          key: token
    volumeMounts:
    - name: fio-config
      mountPath: /etc/fio
      readOnly: true
    - name: tmp
      mountPath: /tmp
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
    readinessProbe:
      httpGet:
        path: /health
        port: 8080
  volumes:
  - name: fio-config
    configMap:
      name: fio-job
  - name: tmp
    emptyDir:
      medium: Memory
```

## Typical Workflow

```bash
# 1. Wait for the pod to be ready
kubectl wait --for=condition=ready pod/fio-bench

# 2. Start the benchmark
kubectl exec fio-bench -- wget -qO- --header="Authorization: Bearer $TOKEN" \
  --post-data='{"args":["/etc/fio/job.fio"]}' http://localhost:8080/start

# 3. Check progress
kubectl exec fio-bench -- wget -qO- --header="Authorization: Bearer $TOKEN" \
  http://localhost:8080/status

# 4. Stop when desired (produces full results)
kubectl exec fio-bench -- wget -qO- --post-data='' \
  --header="Authorization: Bearer $TOKEN" http://localhost:8080/stop

# 5. Retrieve JSON results
kubectl exec fio-bench -- wget -qO- --header="Authorization: Bearer $TOKEN" \
  http://localhost:8080/output > results.json
```

## Structure

```
images/fio/
├── Dockerfile
├── go.mod
├── README.md
└── cmd/fio-controller/
    └── main.go
```
