# Networking

Tasks do not get a Kubernetes Service or Ingress of their own. Every request to a task goes through Agent Substrate's **atenet router**, the `atenet-router` Service in the `ate-system` namespace. The router reads a single header, `ate-target-actor`, resolves the actor to the worker it is running on, resumes it first if it was suspended, and proxies the request there. `Host` and `:authority` are left alone for your application; the header alone selects the target.

The header value is `<atespace>/<task>`. AX always names a task's actor after the task, so `default/task123` reaches the task `task123` in the `default` atespace.

## From inside the cluster

Current Substrate routers use port 443 and require an allowed client SPIFFE identity.
The AX deployment projects its pod identity credential and the serving CA bundle.
Allow `spiffe://cluster.local/ns/ax-system/sa/ax-server` in the router's ingress
configuration (adjust the namespace if needed).

For AX readiness and `ax ssh`, configure:

```bash
export ATENET_ROUTER_CA_FILE=/path/to/serving-ca.pem
export ATENET_ROUTER_CLIENT_CERT=/path/to/credential-bundle.pem
export ATENET_ROUTER_SERVER_NAME=atenet-router.ate-system.svc
```

The credential bundle contains both the client certificate and its private key;
keep it private. Obtain it through your cluster's approved identity flow. AX
reloads these files for new connections, including projected certificate rotation.
TLS verification uses the router DNS name even through a localhost port-forward.
When TLS is configured, `ax ssh` uses the authenticated router directly.

`ax-server` also accepts `ATENET_ROUTER_ADDR` for readiness routing. Set it to
`https://atenet-router.ate-system.svc.cluster.local:443`. The supplied deployment
sets this and the projected credential paths. Invalid or incomplete TLS settings
fail before connecting; they never select plaintext as a fallback.

Use the Service DNS name and add the routing header:

```bash
curl --cacert "$ATENET_ROUTER_CA_FILE" \
  --cert "$ATENET_ROUTER_CLIENT_CERT" --key "$ATENET_ROUTER_CLIENT_CERT" \
  -H "ate-target-actor: default/task123" \
  https://atenet-router.ate-system.svc/readyz
```

## From your machine

Port-forward the router, then talk to it the same way.

```bash
kubectl -n ate-system port-forward svc/atenet-router 8001:443
curl --connect-to atenet-router.ate-system.svc:8001:localhost:8001 \
  --cacert "$ATENET_ROUTER_CA_FILE" \
  --cert "$ATENET_ROUTER_CLIENT_CERT" --key "$ATENET_ROUTER_CLIENT_CERT" \
  -H "ate-target-actor: default/task123" \
  https://atenet-router.ate-system.svc:8001/readyz
```

Older routers exposing plaintext port 80 remain supported when none of the three
TLS variables are set. For those routers, use an HTTP readiness address and
forward port 80.

## gRPC request routing

Send the header as outgoing metadata under the lowercase key. This is what `ax ssh` does to reach the guest services.

```go
ctx = metadata.AppendToOutgoingContext(ctx, "ate-target-actor", "default/task123")
resp, err := client.SomeMethod(ctx, req)
```
