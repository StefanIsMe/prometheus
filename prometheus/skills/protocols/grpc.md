---
name: grpc
description: gRPC security testing covering protobuf injection, reflection abuse, metadata manipulation, authentication bypass, and service enumeration
---

# gRPC Security Testing

gRPC services expose a distinct attack surface over HTTP/2 with Protocol Buffer serialization, service reflection, streaming RPCs, and metadata-based authentication. Misconfigurations in channel security, reflection endpoints, and authorization logic are common and frequently lead to service enumeration, authentication bypass, and data exfiltration.

## Attack Surface

**Scope**
- gRPC services over HTTP/2 (plaintext h2c or TLS h2)
- Protocol Buffer message definitions and serialization
- gRPC metadata headers (equivalent to HTTP headers)
- Server reflection endpoints
- Unary, server-streaming, client-streaming, and bidirectional-streaming RPCs
- gRPC-Web and gRPC-Gateway (REST-to-gRPC) bridges

**Entry Points**
- Exposed server reflection (grpc.reflection.v1.ServerReflection)
- Client-supplied .proto files from open-source repos or leaked SDKs
- Insecure plaintext channels (h2c) without TLS
- gRPC-Web proxies exposing services to browsers
- Load balancers or API gateways terminating TLS with weak config
- Metadata headers carrying auth tokens, tenant IDs, or routing info

**Authentication Methods**
- Metadata headers: `authorization` (Bearer tokens), `x-api-key`, custom headers
- mTLS (mutual TLS) with client certificates
- Per-RPC credentials vs channel-level credentials
- Google-style auth: `authorization: Bearer <token>`

## Key Vulnerabilities

### Server Reflection Abuse

Server reflection exposes the full service schema without needing .proto files. Many deployments leave it enabled in production.

**Test:**
```bash
# List all services
grpcurl -plaintext target:50051 list

# Describe a service (shows methods and message types)
grpcurl -plaintext target:50051 describe myapp.UserService

# Describe a message type (shows all fields)
grpcurl -plaintext target:50051 describe myapp.User

# List all methods on a service
grpcurl -plaintext target:50051 describe myapp.UserService.GetUser
```

**Reflection endpoint check:**
```bash
# If grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo exists,
# reflection is enabled
grpcurl -plaintext target:50051 grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
```

### Service Enumeration

When reflection is disabled, enumerate services through other means:

```bash
# Use grpcurl with proto file
grpcurl -import-path ./protos -proto service.proto -plaintext target:50051 list

# Brute-force common service names
for svc in User Admin Auth Payment Order Health Check; do
  grpcurl -plaintext target:50051 "myapp.${svc}/GetStatus" 2>&1 | grep -v "does not exist"
done

# Extract protos from client apps (Android APK, iOS IPA, Electron apps)
# Look for .proto files or compiled descriptor sets
find . -name "*.proto" -o -name "*.desc" -o -name "*_grpc.py"

# Decompile protobuf from binaries
protoscope -s binary_payload.bin
```

### Insecure Channel Detection

```bash
# Test for plaintext (no TLS) - common in internal services
grpcurl -plaintext target:50051 list

# Check TLS configuration
grpcurl target:50051 list  # Should fail if no TLS

# Test for weak TLS versions
openssl s_client -connect target:50051 -tls1
openssl s_client -connect target:50051 -tls1_1

# Check for h2c upgrade (HTTP/2 cleartext)
curl -s --http2-prior-knowledge http://target:50051/ -v

# Test if mTLS is enforced
grpcurl target:50051 list  # Works without client cert = mTLS not enforced
```

### Authentication Bypass

**Metadata Manipulation:**
```bash
# Send requests without auth metadata
grpcurl -plaintext target:50051 myapp.UserService/GetProfile

# Test with empty token
grpcurl -plaintext -H "authorization: " target:50051 myapp.UserService/GetProfile

# Test with manipulated tokens
grpcurl -plaintext -H "authorization: Bearer forged_token" target:50051 myapp.UserService/GetProfile

# Test custom metadata headers for auth bypass
grpcurl -plaintext -H "x-user-id: 1" target:50051 myapp.UserService/GetProfile
grpcurl -plaintext -H "x-tenant-id: admin" target:50051 myapp.UserService/GetProfile
grpcurl -plaintext -H "x-forwarded-for: 127.0.0.1" target:50051 myapp.UserService/GetProfile
```

**Per-RPC vs Channel Auth Gaps:**
```bash
# Channel-level auth might not apply to individual RPCs
# Test each method independently for auth enforcement
grpcurl -plaintext target:50051 myapp.InternalService/AdminAction
```

### Protobuf Injection & Manipulation

**Type Confusion:**
```bash
# Send unexpected field types
grpcurl -plaintext -d '{"id": 0}' target:50051 myapp.UserService/GetUser
grpcurl -plaintext -d '{"id": -1}' target:50051 myapp.UserService/GetUser
grpcurl -plaintext -d '{"id": 99999999999}' target:50051 myapp.UserService/GetUser
```

**Field Injection:**
```bash
# Include unexpected fields (protobuf ignores unknown fields by default)
grpcurl -plaintext -d '{"id": "1", "admin": true}' target:50051 myapp.UserService/GetUser

# Test default value handling
grpcurl -plaintext -d '{"id": ""}' target:50051 myapp.UserService/GetUser
grpcurl -plaintext -d '{}' target:50051 myapp.UserService/GetUser

# Enum field manipulation
grpcurl -plaintext -d '{"role": 999}' target:50051 myapp.UserService/UpdateRole

# Nested message injection
grpcurl -plaintext -d '{"user": {"id": "1", "metadata": {"admin": true}}}' target:50051 myapp.UserService/UpdateUser
```

**Oneof and Map Abuse:**
```bash
# oneof fields - send multiple fields (only one should be set)
grpcurl -plaintext -d '{"email": "a@b.com", "phone": "123"}' target:50051 myapp.UserService/Lookup

# Map fields - large keys, injection
grpcurl -plaintext -d '{"metadata": {"../../etc/passwd": "value"}}' target:50051 myapp.UserService/SetMetadata
```

### Streaming Endpoint Attacks

```bash
# Server-streaming: trigger large streams for resource exhaustion
grpcurl -plaintext -d '{"limit": 999999}' target:50051 myapp.DataService/StreamAll

# Client-streaming: send rapid messages
for i in $(seq 1 10000); do echo '{"data": "payload_'$i'"}'; done | \
  grpcurl -plaintext -d @ target:50051 myapp.DataService/UploadStream

# Bidirectional: test message ordering and race conditions
grpcurl -plaintext -d @ target:50051 myapp.ChatService/ChatStream

# Test for stream cancellation / resource leak
# Send partial stream then close connection
timeout 1 grpcurl -plaintext -d @ target:50051 myapp.DataService/UploadStream
```

### gRPC-Specific Injection

**Metadata Header Injection:**
```bash
# Binary metadata (suffix with -bin)
grpcurl -plaintext -H "x-token-bin: AAECAwQ=" target:50051 myapp.UserService/GetProfile

# Header smuggling via metadata
grpcurl -plaintext -H "x-real-ip: 127.0.0.1" target:50051 myapp.AdminService/GetDashboard

# Test metadata size limits (potential DoS)
python3 -c "print('x-padding: ' + 'A'*100000)" | \
  xargs -I{} grpcurl -plaintext -H "{}" target:50051 myapp.UserService/GetProfile
```

**Error Message Information Disclosure:**
```bash
# Trigger detailed errors
grpcurl -plaintext -d '{"id": "invalid"}' target:50051 myapp.UserService/GetUser
# Look for stack traces, internal paths, database errors in status details

# Test gRPC status codes for information leakage
# RESOURCE_EXHAUSTED, UNAVAILABLE, INTERNAL often leak server details
```

### gRPC-Web and Gateway Attacks

```bash
# gRPC-Web typically served on HTTP/1.1 or HTTP/2 via Envoy/nginx
# Test CORS on gRPC-Web endpoints
curl -X OPTIONS -H "Origin: https://evil.com" https://target/grpc/myapp.UserService/GetProfile

# REST gateway (grpc-gateway) may expose REST endpoints
curl https://target/api/v1/users/1
# REST auth may differ from gRPC auth

# Content-type switching between gRPC-Web and standard gRPC
curl -H "Content-Type: application/grpc-web" https://target/grpc/myapp.UserService/GetProfile
```

## Bypass Techniques

**Protocol Switching**
- Test both plaintext (h2c) and TLS (h2) channels
- gRPC-Web may have different auth than native gRPC
- REST gateway endpoints may skip gRPC middleware

**Metadata Tricks**
- Case sensitivity: `Authorization` vs `authorization`
- Multiple values for same metadata key
- Binary vs string metadata for the same field

**Load Balancer Bypass**
- Direct connection to backend bypassing L7 load balancer
- L4 load balancers may not inspect gRPC metadata
- Health check endpoints (`grpc.health.v1.Health/Check`) often unauthenticated

## Testing Methodology

1. **Channel probe** - Test plaintext and TLS, check mTLS requirements, identify TLS version
2. **Reflection check** - Try grpc.reflection.v1 and v1alpha for full schema exposure
3. **Service enumeration** - Use reflection, leaked protos, or brute-force to map all services
4. **Auth mapping** - Test each RPC with and without auth metadata, document per-RPC vs channel auth
5. **Input fuzzing** - Type confusion, unknown fields, default values, enum edge cases, oneof conflicts
6. **Streaming tests** - Resource exhaustion, cancellation, message ordering
7. **Metadata abuse** - Header injection, binary metadata, auth bypass via custom headers
8. **Error analysis** - Trigger error conditions, check for info disclosure in status details

## Validation Requirements

- Paired requests (authenticated vs unauthenticated) showing auth bypass
- Service enumeration evidence via reflection or proto extraction
- Proof of insecure channel (plaintext gRPC carrying sensitive data)
- Input manipulation demonstrating business logic bypass
- Streaming abuse demonstrating resource exhaustion potential
- Document exact RPCs and metadata that enabled the bypass

## Tools

- **grpcurl** - CLI for interacting with gRPC servers (list, describe, invoke)
- **grpc-curl** - Alternative gRPC client with different feature set
- **protoscope** - Binary protobuf decoder/analyzer
- **protoc** - Protocol Buffer compiler for .proto analysis
- **grpcui** - Web-based gRPC interactive client
- **mitmproxy** - Proxy with gRPC interception support
- **postman** - gRPC request support with reflection

## Summary

gRPC security failures typically involve: exposed reflection enabling full schema extraction, missing per-RPC auth enforcement, insecure plaintext channels, and protobuf message manipulation. Start with reflection to map the attack surface, then systematically test each RPC for auth bypass and input validation gaps. Streaming endpoints require special attention for resource exhaustion and race conditions.
