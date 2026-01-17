## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CERTIFICATE STORAGE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Working Directory:                      System Trust Store:                │
│  ┌──────────────────┐                    ┌─────────────────────┐           │
│  │ proxy-ca.crt     │ ──── install ────> │ Windows: certutil   │           │
│  │ (Public CA Cert) │                    │ macOS: Keychain     │           │
│  └──────────────────┘                    │ Linux: ca-certs     │           │
│                                           └─────────────────────┘           │
│  ┌──────────────────┐                                                       │
│  │ proxy-ca.key     │ ◄── used to sign                                      │
│  │ (Private CA Key) │     host certs                                        │
│  └──────────────────┘                                                       │
│         │                                                                    │
│         └─────────┐                                                          │
│                   ▼                                                          │
│         ┌──────────────────┐                                                │
│         │ In-Memory Cache  │                                                │
│         │ ┌──────────────┐ │                                                │
│         │ │ example.com  │ │ ◄── Dynamically generated per host            │
│         │ │   cert+key   │ │                                                │
│         │ └──────────────┘ │                                                │
│         │ ┌──────────────┐ │                                                │
│         │ │ google.com   │ │                                                │
│         │ │   cert+key   │ │                                                │
│         │ └──────────────┘ │                                                │
│         └──────────────────┘                                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROXY TRAFFIC FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────┐                                                  ┌─────────┐    │
│  │ Client │                                                  │  Real   │    │
│  │Browser │                                                  │ Server  │    │
│  │  App   │                                                  │(HTTPS)  │    │
│  └────┬───┘                                                  └────▲────┘    │
│       │                                                           │          │
│       │ 1. CONNECT example.com:443                               │          │
│       ├──────────────────────────────────────────────┐           │          │
│       │                                               │           │          │
│       │                    ┌──────────────────────────▼───────────┴─────┐   │
│       │                    │      TLS PROXY (localhost:8080)            │   │
│       │                    │                                            │   │
│       │                    │  ┌──────────────────────────────────────┐ │   │
│       │ 2. HTTP/1.1 200 OK │  │ 1. Receive CONNECT                   │ │   │
│       │◄───────────────────┤  │ 2. Send "200 Connection Established" │ │   │
│       │                    │  │ 3. Get/Generate cert for example.com │ │   │
│       │                    │  │ 4. Start TLS handshake with client   │ │   │
│       │                    │  └──────────────────────────────────────┘ │   │
│       │                    │                                            │   │
│       │ 3. TLS Handshake   │  ┌──────────────────────────────────────┐ │   │
│       │   (Client Hello)   │  │ Present dynamically generated cert   │ │   │
│       ├───────────────────>│  │ signed by proxy-ca.key               │ │   │
│       │                    │  │                                      │ │   │
│       │   (Server Hello +  │  │ Client validates against installed   │ │   │
│       │    example.com     │  │ proxy-ca.crt in trust store         │ │   │
│       │    certificate)    │  └──────────────────────────────────────┘ │   │
│       │◄───────────────────┤                                            │   │
│       │                    │                                            │   │
│       │   [TLS 1.2/1.3     │                                            │   │
│       │    Encrypted]      │                                            │   │
│       │                    └────────────────────────────────────────────┘   │
│       │                                                                     │
│       │ 4. HTTPS Request (decrypted by proxy)                              │
│       │    GET /api/data                                                    │
│       ├────────────────────────────────────┐                                │
│       │                                     │                                │
│       │              ┌──────────────────────▼────────────────────┐          │
│       │              │  PROXY LOGGING                            │          │
│       │              │  ┌─────────────────────────────────────┐  │          │
│       │              │  │ Log to console:                     │  │          │
│       │              │  │ - Connection info                   │  │          │
│       │              │  │ - TLS version & cipher             │  │          │
│       │              │  │ - HTTP method & URL                │  │          │
│       │              │  │ - Headers                          │  │          │
│       │              │  │ - POST parameters                  │  │          │
│       │              │  └─────────────────────────────────────┘  │          │
│       │              │  ┌─────────────────────────────────────┐  │          │
│       │              │  │ Write to proxy.log file             │  │          │
│       │              │  └─────────────────────────────────────┘  │          │
│       │              └───────────────────────────────────────────┘          │
│       │                                     │                                │
│       │                                     │ 5. Forward to real server      │
│       │                                     │    (establish new TLS)         │
│       │                                     └──────────────────────┐         │
│       │                                                            │         │
│       │                                                            ▼         │
│       │                                              ┌──────────────────┐    │
│       │                                              │  example.com:443 │    │
│       │                                              │                  │    │
│       │                                              │  TLS 1.2/1.3    │    │
│       │                                              │  Handshake      │    │
│       │                                              └────────┬─────────┘    │
│       │                                                       │              │
│       │                                              6. GET /api/data        │
│       │                                              ────────────────>       │
│       │                                                       │              │
│       │                                              7. Response             │
│       │                                              <────────────────       │
│       │                                                       │              │
│       │              8. Response (encrypted by proxy)        │              │
│       │◄─────────────────────────────────────────────────────┘              │
│       │                                                                      │
│       ▼                                                                      │
│  [Client receives                                                           │
│   decrypted data]                                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

KEY:
  ──>  : Unencrypted traffic
  ═══> : TLS encrypted traffic
  ┌─┐  : Component/Process
  
SECURITY MODEL:
  1. Proxy acts as Certificate Authority (CA)
  2. Client trusts proxy's CA certificate
  3. Proxy generates unique certs for each domain on-the-fly
  4. Proxy can decrypt, inspect, log, then re-encrypt traffic
  5. Real servers see normal TLS connections from proxy
