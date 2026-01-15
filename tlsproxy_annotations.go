package main

/*
TLS Intercepting Proxy - Educational Overview

This proxy acts as a "man-in-the-middle" to inspect HTTPS traffic. Here's how TLS normally works:
1. Client connects to server and they establish an encrypted tunnel using TLS
2. All data is encrypted so nobody in between can read it
3. This is great for security but makes debugging difficult

This proxy solves the debugging problem by:
1. Acting as a fake server to the client (using certificates we generate)
2. Acting as a real client to the actual server
3. Decrypting traffic from client, inspecting it, then re-encrypting to server
4. This only works if the client trusts our Certificate Authority (CA)

The key insight: If you control the CA that signs certificates, you can decrypt any TLS traffic
that trusts that CA. This is why protecting your system's trusted CA list is so important!
*/

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "proxy-ca.crt"
	caKeyFile  = "proxy-ca.key"
	logFile    = "proxy.log"
)

type ProxyConfig struct {
	Port        int
	CertDir     string
	LogFile     string
	SkipInstall bool
}

/*
Certificate Configuration - Understanding X.509 Certificates

An X.509 certificate is like a digital ID card that proves "I am who I say I am."
It contains information like who issued it (Organization), who it's for (CommonName), and how long it's valid.

Special fields explained:
- SAN (Subject Alternative Names): Allows one cert to work for multiple domains (e.g., example.com AND www.example.com)
- AIA (Authority Information Access): Tells clients where to verify this certificate is legit
- CDP (CRL Distribution Points): Where to check if this certificate has been revoked
- OCSP: Online Certificate Status Protocol - real-time way to check if cert is still valid

For our proxy, we mostly care about CommonName (the domain name) and SAN (alternate names).
The other fields are optional extras that real production CAs use for additional security.
*/
type CertConfig struct {
	Organization      string
	CommonName        string
	ValidityYears     int
	AIAURLs           string // Format: "ocsp_url|ca_issuer_url"
	CRLDistPoints     []string
	OCSPServer        string
	DefaultSANs       []string
	HostValidityDays  int
	IncludeAIAInHosts bool
	IncludeCDPInHosts bool
}

func defaultCertConfig() *CertConfig {
	return &CertConfig{
		Organization:      "TLS Proxy CA",
		CommonName:        "TLS Proxy Root CA",
		ValidityYears:     10,
		AIAURLs:           "",
		CRLDistPoints:     []string{},
		OCSPServer:        "",
		DefaultSANs:       []string{"localhost", "127.0.0.1"},
		HostValidityDays:  365,
		IncludeAIAInHosts: false,
		IncludeCDPInHosts: false,
	}
}

type CertCache struct {
	sync.RWMutex
	certs map[string]*tls.Certificate
}

var (
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	certCache   = &CertCache{certs: make(map[string]*tls.Certificate)}
	certConfig  *CertConfig
	logMutex    sync.Mutex
	logWriter   *os.File
	logModules  []LogModule
)

/*
Logging Module System - The Middleware Pattern

Think of modules as filters in a pipeline. When traffic flows through the proxy:
1. Request comes from client → Each module can inspect and modify it
2. Request goes to server → Server sends response back
3. Response comes back → Each module can inspect and modify it
4. Response goes to client

The LogModule interface defines what each module must be able to do:
- Name(): Identify itself for logging
- ShouldLog(): Decide if this request/response is interesting
- ProcessRequest(): Modify the request before it reaches the server
- ProcessResponse(): Modify the response before it reaches the client

This is called the "middleware pattern" - it's used in web frameworks, proxies, and many systems.
Each module is independent and you can combine them to create powerful workflows!
*/
type LogModule interface {
	Name() string
	ShouldLog(req *http.Request) bool
	ProcessRequest(req *http.Request) error
	ProcessResponse(resp *http.Response) error
}

// RegisterModule adds a logging module to the chain
func RegisterModule(module LogModule) {
	logModules = append(logModules, module)
	log.Printf("[MODULE] Registered: %s", module.Name())
}

// Module execution helpers
func executeModules(req *http.Request) bool {
	shouldLog := false
	for _, module := range logModules {
		if module.ShouldLog(req) {
			shouldLog = true
		}
		if err := module.ProcessRequest(req); err != nil {
			log.Printf("[%s] Error processing request: %v", module.Name(), err)
		}
	}
	return shouldLog
}

func executeModulesResponse(resp *http.Response) error {
	for _, module := range logModules {
		if err := module.ProcessResponse(resp); err != nil {
			log.Printf("[%s] Error processing response: %v", module.Name(), err)
		}
	}
	return nil
}

/*
Console Output Sanitization - Preventing Terminal Chaos

ASCII control characters (values 0-31) have special meanings to terminals:
- 0x07 (bell): Makes the terminal beep
- 0x1B (escape): Starts ANSI escape sequences that can change colors, move cursor, etc.
- 0x08 (backspace): Moves cursor backward, can corrupt output
- 0x0C (form feed): Can clear the screen

If we print these raw to the console, weird things happen:
- Your terminal starts beeping constantly (annoying!)
- Text colors change unexpectedly
- Output gets corrupted or misaligned
- Screen might clear itself

This is especially problematic when logging HTTP responses that might contain:
- Binary data that happens to include control characters
- Malicious responses designed to mess up your terminal
- Compressed data before we decompress it

Our solution: Replace control characters with their hex representation:
- Bell (0x07) becomes the visible text "\x07"
- Escape (0x1B) becomes "\x1b"
- Now you can see what the character is without it affecting your terminal!

We keep newlines, tabs, and carriage returns because those are useful for formatting.
We keep Unicode (values >= 128) because that's normal international text.
Only the dangerous ASCII control characters (0-31) get escaped!
*/
func sanitizeForConsole(data string) string {
	var result strings.Builder
	result.Grow(len(data))
	
	for _, r := range data {
		// Allow printable ASCII, newline, tab, and carriage return
		if r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		} else if r >= 32 && r < 127 {
			// Printable ASCII
			result.WriteRune(r)
		} else if r >= 128 {
			// Unicode characters (keep them)
			result.WriteRune(r)
		} else {
			// Replace control characters with hex notation
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	
	return result.String()
}

// isBinaryContent checks if content appears to be binary
func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// Sample first 512 bytes
	sampleSize := 512
	if len(data) < sampleSize {
		sampleSize = len(data)
	}
	
	nullCount := 0
	controlCount := 0
	
	for i := 0; i < sampleSize; i++ {
		b := data[i]
		if b == 0 {
			nullCount++
		}
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			controlCount++
		}
	}
	
	// If more than 10% null bytes or 30% control chars, consider binary
	return nullCount > sampleSize/10 || controlCount > sampleSize*3/10
}

// ==================== BUILT-IN LOGGING MODULES ====================

// AllTrafficModule logs all traffic (default behavior)
type AllTrafficModule struct{}

func (m *AllTrafficModule) Name() string {
	return "AllTraffic"
}

func (m *AllTrafficModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *AllTrafficModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *AllTrafficModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// OAuthModule only logs OAuth/authentication flows
type OAuthModule struct{}

func (m *OAuthModule) Name() string {
	return "OAuth"
}

func (m *OAuthModule) ShouldLog(req *http.Request) bool {
	url := req.URL.String()
	path := strings.ToLower(req.URL.Path)
	
	// Check for OAuth patterns
	oauthPatterns := []string{
		"/oauth", "/auth", "/login", "/token", "/authorize",
		"access_token", "refresh_token", "client_id", "client_secret",
		"/connect", "/callback", "/.well-known/openid",
	}
	
	for _, pattern := range oauthPatterns {
		if strings.Contains(strings.ToLower(url), pattern) || 
		   strings.Contains(path, pattern) {
			log.Printf("[OAuth] Detected OAuth flow: %s", url)
			return true
		}
	}
	
	// Check Authorization header
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		log.Printf("[OAuth] Detected Authorization header")
		return true
	}
	
	return false
}

func (m *OAuthModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *OAuthModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// DomainFilterModule only logs specific domains
type DomainFilterModule struct {
	Domains []string
}

func (m *DomainFilterModule) Name() string {
	return fmt.Sprintf("DomainFilter(%s)", strings.Join(m.Domains, ","))
}

func (m *DomainFilterModule) ShouldLog(req *http.Request) bool {
	host := req.URL.Hostname()
	for _, domain := range m.Domains {
		if strings.Contains(host, domain) {
			return true
		}
	}
	return false
}

func (m *DomainFilterModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *DomainFilterModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// RequestModifierModule modifies requests (example: add headers)
type RequestModifierModule struct {
	AddHeaders    map[string]string
	RemoveHeaders []string
}

func (m *RequestModifierModule) Name() string {
	return "RequestModifier"
}

func (m *RequestModifierModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *RequestModifierModule) ProcessRequest(req *http.Request) error {
	// Add custom headers
	for key, value := range m.AddHeaders {
		req.Header.Set(key, value)
		log.Printf("[RequestModifier] Added header: %s: %s", key, value)
	}
	
	// Remove headers
	for _, key := range m.RemoveHeaders {
		if req.Header.Get(key) != "" {
			req.Header.Del(key)
			log.Printf("[RequestModifier] Removed header: %s", key)
		}
	}
	
	return nil
}

func (m *RequestModifierModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// ResponseModifierModule modifies responses
type ResponseModifierModule struct {
	AddHeaders    map[string]string
	RemoveHeaders []string
}

func (m *ResponseModifierModule) Name() string {
	return "ResponseModifier"
}

func (m *ResponseModifierModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *ResponseModifierModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *ResponseModifierModule) ProcessResponse(resp *http.Response) error {
	// Add custom headers
	for key, value := range m.AddHeaders {
		resp.Header.Set(key, value)
		log.Printf("[ResponseModifier] Added header: %s: %s", key, value)
	}
	
	// Remove headers
	for _, key := range m.RemoveHeaders {
		if resp.Header.Get(key) != "" {
			resp.Header.Del(key)
			log.Printf("[ResponseModifier] Removed header: %s", key)
		}
	}
	
	return nil
}

// PathFilterModule only logs specific URL paths
type PathFilterModule struct {
	Paths []string
}

func (m *PathFilterModule) Name() string {
	return fmt.Sprintf("PathFilter(%s)", strings.Join(m.Paths, ","))
}

func (m *PathFilterModule) ShouldLog(req *http.Request) bool {
	path := req.URL.Path
	for _, filterPath := range m.Paths {
		if strings.Contains(path, filterPath) {
			return true
		}
	}
	return false
}

func (m *PathFilterModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *PathFilterModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// StringReplacementModule replaces strings in request/response bodies
type StringReplacementModule struct {
	Replacements map[string]string // old -> new
}

func (m *StringReplacementModule) Name() string {
	return "StringReplacement"
}

func (m *StringReplacementModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *StringReplacementModule) ProcessRequest(req *http.Request) error {
	if req.Body == nil {
		return nil
	}

	// Only process text content types
	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		isText := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") ||
			strings.Contains(contentType, "application/x-www-form-urlencoded") ||
			strings.Contains(contentType, "application/javascript")
		
		if !isText {
			// Not text content, skip replacement
			return nil
		}
	}

	// Handle Content-Encoding (decompress if needed)
	var reader io.Reader = req.Body
	encoding := req.Header.Get("Content-Encoding")
	
	if encoding == "gzip" {
		gzipReader, err := gzip.NewReader(req.Body)
		if err != nil {
			// Not valid gzip, try reading as-is
			log.Printf("[StringReplacement] Warning: Failed to decompress gzip request: %v", err)
			reader = req.Body
		} else {
			reader = gzipReader
			defer gzipReader.Close()
		}
	}

	// Read the body (decompressed if it was compressed)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Close the original body
	req.Body.Close()

	// Apply replacements
	bodyStr := string(bodyBytes)
	for old, new := range m.Replacements {
		if strings.Contains(bodyStr, old) {
			count := strings.Count(bodyStr, old)
			bodyStr = strings.ReplaceAll(bodyStr, old, new)
			log.Printf("[StringReplacement] Request: Replaced '%s' with '%s' (%d occurrences)", old, new, count)
		}
	}

	// Create new body with modified content (uncompressed)
	req.Body = io.NopCloser(bytes.NewBufferString(bodyStr))
	req.ContentLength = int64(len(bodyStr))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
	
	// Remove Content-Encoding since we're returning uncompressed data
	if encoding != "" {
		req.Header.Del("Content-Encoding")
		log.Printf("[StringReplacement] Removed Content-Encoding: %s (returning uncompressed)", encoding)
	}

	return nil
}

/*
String Replacement in Compressed Responses - The Compression Challenge

Web servers compress responses to save bandwidth. Common formats:
- gzip: Standard compression (60-80% size reduction) - WE SUPPORT THIS
- Brotli (br): Google's newer algorithm (5-10% better than gzip) - WE DON'T SUPPORT THIS
- zstd: Facebook's compression - WE DON'T SUPPORT THIS
- deflate: Older compression - WE DON'T SUPPORT THIS

The challenge: We can't search for "cyber" in compressed data because it looks like:
  Uncompressed: "cyber security is important"
  Gzip: \x1f\x8b\x08\x00... (binary gibberish)

Our solution:
1. Check Content-Encoding header to see what compression is used
2. If it's gzip → decompress it using Go's gzip library
3. If it's Brotli/zstd/deflate → skip it (Go standard library doesn't support these)
4. Do string replacement on the decompressed text
5. Return the modified text UNCOMPRESSED (updating Content-Length header)

Why return uncompressed? Re-compressing would require extra CPU and complexity.
The browser handles uncompressed data just fine, and for debugging we prefer readability.

This is why ForceGzipModule is important - it tells servers "only send me gzip, not Brotli!"
*/
func (m *StringReplacementModule) ProcessResponse(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}

	// Only process text content types
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		isText := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") ||
			strings.Contains(contentType, "application/javascript")
		
		if !isText {
			// Not text content, skip replacement
			return nil
		}
	}

	// Handle Content-Encoding (decompress if needed)
	encoding := resp.Header.Get("Content-Encoding")
	
	// Skip unsupported compression formats
	if encoding == "br" || encoding == "zstd" || encoding == "deflate" {
		log.Printf("[StringReplacement] Warning: Skipping response with unsupported compression: %s (only gzip is supported)", encoding)
		log.Printf("[StringReplacement] Tip: To enable replacements, disable %s in browser or use Accept-Encoding header filter", encoding)
		return nil
	}
	
	var reader io.Reader = resp.Body
	
	if encoding == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Not valid gzip, try reading as-is
			log.Printf("[StringReplacement] Warning: Failed to decompress gzip response: %v", err)
			reader = resp.Body
		} else {
			reader = gzipReader
			defer gzipReader.Close()
		}
	}

	// Read the body (decompressed if it was compressed)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Close the original body
	resp.Body.Close()

	// Apply replacements
	bodyStr := string(bodyBytes)
	for old, new := range m.Replacements {
		if strings.Contains(bodyStr, old) {
			count := strings.Count(bodyStr, old)
			bodyStr = strings.ReplaceAll(bodyStr, old, new)
			log.Printf("[StringReplacement] Response: Replaced '%s' with '%s' (%d occurrences)", old, new, count)
		}
	}

	// Create new body with modified content (uncompressed)
	resp.Body = io.NopCloser(bytes.NewBufferString(bodyStr))
	resp.ContentLength = int64(len(bodyStr))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
	
	// Remove Content-Encoding since we're returning uncompressed data
	if encoding != "" && encoding != "br" && encoding != "zstd" && encoding != "deflate" {
		resp.Header.Del("Content-Encoding")
		log.Printf("[StringReplacement] Removed Content-Encoding: %s (returning uncompressed)", encoding)
	}

	return nil
}

/*
Force Gzip Module - Content Negotiation Manipulation

HTTP content negotiation is how browsers and servers agree on compression format.
The browser sends: Accept-Encoding: gzip, deflate, br, zstd
This means: "I can handle gzip, deflate, Brotli, or zstd compression - you choose!"

The server usually picks the best one (Brotli is most efficient).
But we have a problem: Go's standard library only supports gzip decompression.

This module solves it by:
1. Intercepting the request before it goes to the server
2. Modifying Accept-Encoding header to ONLY include gzip
3. Server sees: Accept-Encoding: gzip
4. Server responds with gzip compression (because that's the only option we claim to support)
5. Now StringReplacementModule can decompress and modify the response!

Think of it like ordering food and saying "I'm allergic to everything except pizza."
The restaurant will serve you pizza because that's all you can have.
Similarly, by claiming we only support gzip, servers send us gzip!

This is a common technique in HTTP proxy development when you need to process compressed content
but don't have all the decompression libraries available.
*/
type ForceGzipModule struct{}

func (m *ForceGzipModule) Name() string {
	return "ForceGzip"
}

func (m *ForceGzipModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *ForceGzipModule) ProcessRequest(req *http.Request) error {
	// Get current Accept-Encoding
	acceptEncoding := req.Header.Get("Accept-Encoding")
	
	if acceptEncoding == "" {
		return nil
	}
	
	// Remove br (Brotli), zstd, and deflate - keep only gzip
	encodings := strings.Split(acceptEncoding, ",")
	var supported []string
	
	for _, enc := range encodings {
		enc = strings.TrimSpace(enc)
		// Keep gzip and identity, remove others
		if strings.Contains(enc, "gzip") || enc == "identity" {
			supported = append(supported, enc)
		}
	}
	
	if len(supported) == 0 {
		// If nothing left, request gzip explicitly
		supported = []string{"gzip"}
	}
	
	newAcceptEncoding := strings.Join(supported, ", ")
	
	if newAcceptEncoding != acceptEncoding {
		req.Header.Set("Accept-Encoding", newAcceptEncoding)
		log.Printf("[ForceGzip] Modified Accept-Encoding from '%s' to '%s'", acceptEncoding, newAcceptEncoding)
	}
	
	return nil
}

func (m *ForceGzipModule) ProcessResponse(resp *http.Response) error {
	return nil
}

/*
Main Function - The Proxy Startup Sequence

When you run this program, here's what happens in order:

1. Parse command-line flags (port number, certificate directory, etc.)
2. Load or create the CA certificate:
   - If proxy-ca.crt exists → load it
   - If not → generate new CA and install to OS trust store
3. Open the log file for writing traffic logs
4. Initialize logging modules (filters and modifiers for traffic)
5. Start listening on the specified port (default 8080)
6. For each incoming connection:
   - Spawn a new goroutine (lightweight thread) to handle it
   - This allows handling thousands of connections simultaneously
7. Each connection handler:
   - Reads the HTTP request
   - If CONNECT → establish TLS tunnel (HTTPS)
   - If regular → forward HTTP request
   - Log the traffic
   - Apply any modules (OAuth filter, string replacement, etc.)

The program runs forever in a loop accepting connections until you press Ctrl+C.

Key Go concepts used:
- Goroutines: "go handleConnection()" spawns a concurrent handler
- Defer: "defer file.Close()" ensures cleanup happens even if errors occur
- Error handling: Every operation checks for errors and handles them appropriately
*/
func main() {
	port := flag.Int("port", 8080, "Proxy port")
	cleanup := flag.Bool("cleanup", false, "Remove CA certificates and exit")
	certDir := flag.String("certdir", ".", "Certificate directory")
	skipInstall := flag.Bool("skip-install", false, "Skip automatic certificate installation")
	configFile := flag.String("config", "proxy-config.ini", "Configuration file path")
	flag.Parse()

	// Load certificate configuration
	certConfig = loadConfig(*configFile)

	config := &ProxyConfig{
		Port:        *port,
		CertDir:     *certDir,
		LogFile:     filepath.Join(*certDir, logFile),
		SkipInstall: *skipInstall,
	}

	if *cleanup {
		cleanupCerts(config)
		return
	}

	if err := initCA(config); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	var err error
	logWriter, err = os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logWriter.Close()

	// Initialize logging modules
	initializeModules()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %d", config.Port)
	log.Printf("CA certificate: %s", filepath.Join(config.CertDir, caCertFile))
	log.Printf("Log file: %s", config.LogFile)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, config)
	}
}

func initializeModules() {
	log.Println("Initializing logging modules...")
	
	// Default: Log all traffic
	RegisterModule(&AllTrafficModule{})
	
	// Uncomment to enable OAuth-only logging:
	// RegisterModule(&OAuthModule{})
	
	// Uncomment to filter by domain (example: only log example.com and api.example.com):
	// RegisterModule(&DomainFilterModule{
	// 	Domains: []string{"example.com", "api.example.com"},
	// })
	
	// Uncomment to filter by path (example: only log /api/ endpoints):
	// RegisterModule(&PathFilterModule{
	// 	Paths: []string{"/api/", "/v1/"},
	// })
	
	// Uncomment to modify requests (example: add custom headers):
	// RegisterModule(&RequestModifierModule{
	// 	AddHeaders: map[string]string{
	// 		"X-Proxy-Debug": "true",
	// 		"X-Custom-Header": "value",
	// 	},
	// 	RemoveHeaders: []string{"User-Agent"},
	// })
	
	// Uncomment to modify responses:
	// RegisterModule(&ResponseModifierModule{
	// 	AddHeaders: map[string]string{
	// 		"X-Proxy-Modified": "true",
	// 	},
	// 	RemoveHeaders: []string{"Server"},
	// })
	
	// Uncomment to replace strings in request/response bodies:
	// NOTE: Also enable ForceGzip module to handle Brotli compression
	// RegisterModule(&ForceGzipModule{})
	// RegisterModule(&StringReplacementModule{
	// 	Replacements: map[string]string{
	// 		"cyber":    "kitten",
	// 		"hacker":   "cat lover",
	// 		"security": "cuddles",
	// 	},
	// })
	
	log.Printf("Total modules registered: %d", len(logModules))
}

func loadConfig(configPath string) *CertConfig {
	config := defaultCertConfig()

	if !fileExists(configPath) {
		log.Printf("Config file not found: %s (using defaults)", configPath)
		return config
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Failed to read config file: %v (using defaults)", err)
		return config
	}

	lines := strings.Split(string(data), "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Key-value pair
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

		// Parse based on section and key
		switch currentSection {
		case "ca_certificate":
			switch key {
			case "organization":
				config.Organization = value
			case "common_name":
				config.CommonName = value
			case "validity_years":
				if v, err := parseInt(value); err == nil {
					config.ValidityYears = v
				}
			}
		case "certificate_extensions":
			switch key {
			case "aia_urls":
				config.AIAURLs = value
			case "crl_distribution_points":
				if value != "" {
					config.CRLDistPoints = strings.Split(value, ",")
					for i := range config.CRLDistPoints {
						config.CRLDistPoints[i] = strings.TrimSpace(config.CRLDistPoints[i])
					}
				}
			case "ocsp_url":
				config.OCSPServer = value
			}
		case "host_certificates":
			switch key {
			case "default_san_entries":
				if value != "" {
					config.DefaultSANs = strings.Split(value, ",")
					for i := range config.DefaultSANs {
						config.DefaultSANs[i] = strings.TrimSpace(config.DefaultSANs[i])
					}
				}
			case "validity_days":
				if v, err := parseInt(value); err == nil {
					config.HostValidityDays = v
				}
			case "include_aia_in_host_certs":
				config.IncludeAIAInHosts = parseBool(value)
			case "include_cdp_in_host_certs":
				config.IncludeCDPInHosts = parseBool(value)
			}
		}
	}

	log.Printf("Loaded configuration from: %s", configPath)
	return config
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func parseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "true" || s == "yes" || s == "1" || s == "on"
}

func initCA(config *ProxyConfig) error {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		return loadCA(certPath, keyPath)
	}

	return generateCA(certPath, keyPath, config.SkipInstall)
}

/*
Certificate Authority (CA) Generation - The Root of Trust

A Certificate Authority is like the government agency that issues passports - everyone trusts it.
When we create a CA certificate, we're creating our own "government" that can issue certificates.

Here's what happens:
1. Generate a private key (RSA 2048-bit) - this is our master signing key
2. Create a certificate that says "I am a CA and I can sign other certificates"
3. Self-sign it (we sign our own certificate because we're the root authority)
4. Save both the certificate (public) and private key (secret)
5. Install the certificate in the OS trust store so browsers trust it

Important flags:
- IsCA: true - This certificate can sign other certificates
- KeyUsageCertSign - This key can be used to sign certificates
- MaxPathLen: 1 - This CA can only sign end-entity certificates (not other CAs)

Once installed, any certificate we sign with this CA will be trusted by the browser!
*/
func generateCA(certPath, keyPath string, skipInstall bool) error {
	log.Println("Generating new CA certificate...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   certConfig.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certConfig.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Add CRL Distribution Points if configured
	if len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
		log.Printf("CA CRL Distribution Points: %v", certConfig.CRLDistPoints)
	}

	// Add OCSP and CA Issuer URLs if configured
	if certConfig.AIAURLs != "" {
		parts := strings.Split(certConfig.AIAURLs, "|")
		if len(parts) == 2 {
			ocspURL := strings.TrimSpace(parts[0])
			caIssuerURL := strings.TrimSpace(parts[1])
			
			if ocspURL != "" {
				template.OCSPServer = []string{ocspURL}
				log.Printf("CA OCSP Server: %s", ocspURL)
			}
			if caIssuerURL != "" {
				template.IssuingCertificateURL = []string{caIssuerURL}
				log.Printf("CA Issuer URL: %s", caIssuerURL)
			}
		}
	} else if certConfig.OCSPServer != "" {
		template.OCSPServer = []string{certConfig.OCSPServer}
		log.Printf("CA OCSP Server: %s", certConfig.OCSPServer)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyOut.Close()

	log.Printf("CA certificate generated: %s", certPath)
	log.Printf("CA Organization: %s", certConfig.Organization)
	log.Printf("CA Common Name: %s", certConfig.CommonName)
	log.Printf("CA Validity: %d years", certConfig.ValidityYears)
	
	if skipInstall {
		log.Println("Skipping automatic certificate installation (--skip-install flag)")
		printManualInstallInstructions(certPath)
	} else {
		if err := installCertificate(certPath); err != nil {
			log.Printf("WARNING: Failed to install certificate automatically: %v", err)
			log.Printf("Please install manually: %s", certPath)
			printManualInstallInstructions(certPath)
		} else {
			log.Printf("CA certificate installed successfully")
			log.Printf("You may need to restart your browser for changes to take effect")
		}
	}

	return loadCA(certPath, keyPath)
}

func loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode key PEM")
	}

	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	log.Println("Loaded existing CA certificate")
	return nil
}

func cleanupCerts(config *ProxyConfig) {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	// Uninstall from system
	log.Println("Removing certificate from system trust store...")
	if err := uninstallCertificate(); err != nil {
		log.Printf("WARNING: Failed to uninstall certificate: %v", err)
		log.Println("You may need to remove it manually")
	} else {
		log.Println("Certificate uninstalled from system")
	}

	removed := false
	if fileExists(certPath) {
		os.Remove(certPath)
		log.Printf("Removed: %s", certPath)
		removed = true
	}
	if fileExists(keyPath) {
		os.Remove(keyPath)
		log.Printf("Removed: %s", keyPath)
		removed = true
	}
	if !removed {
		log.Println("No certificate files found to remove")
	}
}

func handleConnection(clientConn net.Conn, config *ProxyConfig) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("[CONNECTION] New connection from %s", clientAddr)

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[ERROR] Failed to read request from %s: %v", clientAddr, err)
		return
	}

	if req.Method == http.MethodConnect {
		log.Printf("[CONNECT] %s -> %s", clientAddr, req.Host)
		handleConnect(clientConn, req, config)
	} else {
		log.Printf("[HTTP] %s %s", req.Method, req.URL.String())
		handleHTTP(clientConn, req, config)
	}
}

/*
HTTPS CONNECT Method - The Tunnel Establishment

When a browser wants to access HTTPS sites through a proxy, it uses the HTTP CONNECT method.
This is different from regular HTTP requests. Here's the sequence:

1. Browser sends: "CONNECT example.com:443 HTTP/1.1"
   (This means: "Please create a tunnel to example.com port 443")

2. Proxy responds: "HTTP/1.1 200 Connection Established"
   (This means: "OK, tunnel is ready, send your TLS traffic")

3. At this point, a raw TCP tunnel exists between browser and proxy
   Now the proxy performs the MITM:

4. Proxy wraps the connection with TLS using our fake certificate for example.com
5. Browser performs TLS handshake and validates the certificate (signed by our CA - trusted!)
6. Browser thinks it has a secure connection to example.com (but it's actually to our proxy)
7. Proxy can now decrypt all HTTPS requests, inspect them, and forward to real server

The cipher suites specified here determine how the encryption works (AES-GCM, ChaCha20, etc.).
We support both TLS 1.2 (older but widely compatible) and TLS 1.3 (newer and more secure).
*/
func handleConnect(clientConn net.Conn, req *http.Request, config *ProxyConfig) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert := getCertForHost(host)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (automatically used for TLS 1.3)
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2 cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: false,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	defer tlsClientConn.Close()

	// Log TLS version
	state := tlsClientConn.ConnectionState()
	tlsVersion := "unknown"
	switch state.Version {
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}
	log.Printf("[TLS] %s using %s with cipher %s", host, tlsVersion, tls.CipherSuiteName(state.CipherSuite))

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to read HTTPS request: %v", err)
			}
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = req.Host

		logRequest(req, config)

		resp, err := forwardRequest(req)
		if err != nil {
			log.Printf("Failed to forward request: %v", err)
			tlsClientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		if err := resp.Write(tlsClientConn); err != nil {
			log.Printf("Failed to write response: %v", err)
			return
		}
		resp.Body.Close()
	}
}

func handleHTTP(clientConn net.Conn, req *http.Request, config *ProxyConfig) {
	defer clientConn.Close()

	if !req.URL.IsAbs() {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}

	logRequest(req, config)

	resp, err := forwardRequest(req)
	if err != nil {
		log.Printf("Failed to forward HTTP request: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Write(clientConn)
}

/*
Request Forwarding - Acting as the Real Client

After we've intercepted and decrypted the client's request, we need to forward it to the real server.
This function acts as a legitimate HTTPS client connecting to the actual destination.

The process:
1. Take the decrypted request from the client
2. Create a NEW TLS connection to the real server (example.com)
3. Send the request to the real server
4. Receive the response from the real server
5. Return it to our calling code (which will then encrypt it and send to client)

Key points:
- We use the REAL server's certificate (not our fake one)
- The server has no idea we're a proxy - we look like a normal browser client
- We support the same TLS versions (1.2 and 1.3) for compatibility
- CheckRedirect: http.ErrUseLastResponse means we don't follow redirects automatically
  (we let the client decide whether to follow redirects)

This creates TWO separate TLS connections:
- Connection 1: Client ←→ Proxy (using our fake certificate)
- Connection 2: Proxy ←→ Real Server (using real certificate)

The proxy sits in the middle, decrypting from both sides!
*/
func forwardRequest(req *http.Request) (*http.Response, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	outReq := &http.Request{
		Method: req.Method,
		URL:    req.URL,
		Header: req.Header.Clone(),
		Body:   req.Body,
	}

	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Connection")

	resp, err := client.Do(outReq)
	if err != nil {
		return nil, err
	}
	
	// Process response through modules
	executeModulesResponse(resp)
	
	return resp, nil
}

func logRequest(req *http.Request, config *ProxyConfig) {
	// Check if any module wants to log this request
	shouldLog := executeModules(req)
	
	if !shouldLog {
		return
	}
	
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("\n=== %s ===\n", timestamp)
	logEntry = logEntry + fmt.Sprintf("%s %s\n", req.Method, req.URL.String())

	logEntry = logEntry + "Headers:\n"
	for name, values := range req.Header {
		for _, value := range values {
			logEntry = logEntry + fmt.Sprintf("  %s: %s\n", name, value)
		}
	}

	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			contentType := req.Header.Get("Content-Type")
			
			// Check if content is binary
			if isBinaryContent(bodyBytes) {
				logEntry = logEntry + fmt.Sprintf("Body: [Binary data, %d bytes]\n", len(bodyBytes))
			} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				params, err := url.ParseQuery(string(bodyBytes))
				if err == nil && len(params) > 0 {
					logEntry = logEntry + "POST Parameters:\n"
					for key, values := range params {
						for _, value := range values {
							logEntry = logEntry + fmt.Sprintf("  %s: %s\n", key, value)
						}
					}
				}
			} else if len(bodyBytes) > 0 {
				// Limit body size in logs
				maxBodySize := 10240 // 10KB
				bodyStr := string(bodyBytes)
				if len(bodyBytes) > maxBodySize {
					bodyStr = string(bodyBytes[:maxBodySize]) + fmt.Sprintf("... [truncated, %d more bytes]", len(bodyBytes)-maxBodySize)
				}
				logEntry = logEntry + fmt.Sprintf("Body: %s\n", bodyStr)
			}
		}
	}

	// Sanitize for console output (prevent beeping)
	consoleEntry := sanitizeForConsole(logEntry)
	fmt.Print(consoleEntry)

	// Write raw data to file
	logWriter.WriteString(logEntry)
}

func getCertForHost(host string) *tls.Certificate {
	hostname := strings.Split(host, ":")[0]

	certCache.RLock()
	cert, exists := certCache.certs[hostname]
	certCache.RUnlock()

	if exists {
		return cert
	}

	certCache.Lock()
	defer certCache.Unlock()

	if cert, exists := certCache.certs[hostname]; exists {
		return cert
	}

	cert = generateCertForHost(hostname)
	certCache.certs[hostname] = cert
	return cert
}

/*
Per-Host Certificate Generation - Dynamic Certificate Forgery

When a client connects to example.com through our proxy, we need to pretend to be example.com.
To do this, we dynamically generate a certificate that says "I am example.com" and sign it with our CA.

Here's the process:
1. Client requests example.com
2. We generate a brand new certificate for example.com on-the-fly
3. We sign it with our CA private key (making it trusted)
4. We present this certificate to the client
5. Client checks: "Is this signed by a CA I trust?" → Yes! (our CA)
6. Client thinks it's talking to real example.com, but it's talking to us

This is called "certificate spoofing" or "MITM certificate generation."
The wildcard SAN (*.example.com) means the cert works for api.example.com, www.example.com, etc.
We cache certificates so we don't regenerate them for every request (performance optimization).

In real attacks, this is how hackers intercept HTTPS. In debugging, it's how we inspect our own traffic!
*/
func generateCertForHost(hostname string) *tls.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Build SAN entries
	sanDNSNames := []string{hostname}
	sanIPAddresses := []net.IP{}

	// Add default SANs from config
	for _, san := range certConfig.DefaultSANs {
		// Check if it's an IP address
		if ip := net.ParseIP(san); ip != nil {
			sanIPAddresses = append(sanIPAddresses, ip)
		} else {
			// Add as DNS name if not already present
			isDuplicate := false
			for _, existing := range sanDNSNames {
				if existing == san {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				sanDNSNames = append(sanDNSNames, san)
			}
		}
	}

	// Check if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		sanIPAddresses = append(sanIPAddresses, ip)
	}

	// Add wildcard if hostname has subdomain
	if strings.Count(hostname, ".") > 1 {
		parts := strings.SplitN(hostname, ".", 2)
		wildcard := fmt.Sprintf("*.%s", parts[1])
		sanDNSNames = append(sanDNSNames, wildcard)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, certConfig.HostValidityDays),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    sanDNSNames,
		IPAddresses: sanIPAddresses,
	}

	// Add CRL Distribution Points if configured and enabled
	if certConfig.IncludeCDPInHosts && len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
	}

	// Add OCSP/AIA if configured and enabled
	if certConfig.IncludeAIAInHosts {
		if certConfig.AIAURLs != "" {
			parts := strings.Split(certConfig.AIAURLs, "|")
			if len(parts) == 2 {
				ocspURL := strings.TrimSpace(parts[0])
				caIssuerURL := strings.TrimSpace(parts[1])
				
				if ocspURL != "" {
					template.OCSPServer = []string{ocspURL}
				}
				if caIssuerURL != "" {
					template.IssuingCertificateURL = []string{caIssuerURL}
				}
			}
		} else if certConfig.OCSPServer != "" {
			template.OCSPServer = []string{certConfig.OCSPServer}
		}
	}

	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &certPrivKey.PublicKey, caKey)

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  certPrivKey,
	}

	return cert
}

func installCertificate(certPath string) error {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}

	switch runtime.GOOS {
	case "windows":
		return installCertWindows(absPath)
	case "darwin":
		return installCertMacOS(absPath)
	case "linux":
		return installCertLinux(absPath)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func installCertWindows(certPath string) error {
	// Check if certutil exists
	_, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found in PATH - manual installation required")
	}

	log.Printf("Installing certificate to Windows trust store...")
	log.Printf("Running: certutil -addstore -user Root \"%s\"", certPath)
	
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	output, err := cmd.CombinedOutput()
	
	// Always show output for debugging
	if len(output) > 0 {
		log.Printf("certutil output: %s", string(output))
	}
	
	if err != nil {
		return fmt.Errorf("certutil failed: %v - %s", err, string(output))
	}
	
	// Verify installation
	log.Printf("Verifying certificate installation...")
	verifyCmd := exec.Command("certutil", "-user", "-verifystore", "Root", "TLS Proxy Root CA")
	verifyOutput, verifyErr := verifyCmd.CombinedOutput()
	
	if verifyErr != nil {
		log.Printf("Warning: Could not verify certificate installation: %v", verifyErr)
		log.Printf("Verification output: %s", string(verifyOutput))
		return fmt.Errorf("certificate may not be installed correctly - please check manually")
	}
	
	log.Printf("Certificate verified in trust store")
	return nil
}

func installCertMacOS(certPath string) error {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", 
		"-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func installCertLinux(certPath string) error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"
	
	// Copy certificate
	input, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	
	cmd := exec.Command("sudo", "tee", destPath)
	cmd.Stdin = bytes.NewReader(input)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}
	
	// Update CA certificates
	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	
	return nil
}

func uninstallCertificate() error {
	switch runtime.GOOS {
	case "windows":
		return uninstallCertWindows()
	case "darwin":
		return uninstallCertMacOS()
	case "linux":
		return uninstallCertLinux()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func uninstallCertWindows() error {
	cmd := exec.Command("certutil", "-delstore", "-user", "Root", "TLS Proxy Root CA")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertMacOS() error {
	cmd := exec.Command("sudo", "security", "delete-certificate", "-c", "TLS Proxy Root CA",
		"/Library/Keychains/System.keychain")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertLinux() error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"
	
	cmd := exec.Command("sudo", "rm", "-f", destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove certificate: %v", err)
	}
	
	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	
	return nil
}

func printManualInstallInstructions(certPath string) {
	absPath, _ := filepath.Abs(certPath)
	
	switch runtime.GOOS {
	case "windows":
		log.Println("")
		log.Println("=== Manual Windows Installation ===")
		log.Println("Option 1 - Command Line (User Store):")
		log.Printf("  certutil -addstore -user Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 2 - Command Line (System Store, requires Admin):")
		log.Printf("  certutil -addstore Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 3 - GUI:")
		log.Printf("  1. Double-click: %s", absPath)
		log.Println("  2. Click 'Install Certificate'")
		log.Println("  3. Store Location: 'Current User'")
		log.Println("  4. Place in: 'Trusted Root Certification Authorities'")
		log.Println("  5. Click 'Next' and 'Finish'")
		log.Println("")
		log.Println("To verify installation:")
		log.Println("  certutil -user -verifystore Root \"TLS Proxy Root CA\"")
		log.Println("")
	case "darwin":
		log.Println("")
		log.Println("=== Manual macOS Installation ===")
		log.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"%s\"", absPath)
		log.Println("")
		log.Println("OR double-click the certificate and set to 'Always Trust'")
		log.Println("")
	case "linux":
		log.Println("")
		log.Println("=== Manual Linux Installation ===")
		log.Printf("  sudo cp \"%s\" /usr/local/share/ca-certificates/tlsproxy.crt", absPath)
		log.Println("  sudo update-ca-certificates")
		log.Println("")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
