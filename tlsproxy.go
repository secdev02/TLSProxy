package main

/*
TLS Intercepting Proxy with Web Monitor - Educational Overview

This proxy acts as a "man-in-the-middle" to inspect HTTPS traffic. Here's how TLS normally works:
1. Client connects to server and they establish an encrypted tunnel using TLS
2. All data is encrypted so nobody in between can read it
3. This is great for security but makes debugging difficult

This proxy solves the debugging problem by:
1. Acting as a fake server to the client (using certificates we generate)
2. Acting as a real client to the actual server
3. Decrypting traffic from client, inspecting it, then re-encrypting to server
4. This only works if the client trusts our Certificate Authority (CA)

NEW: Web-based monitor on port 4040 shows all intercepted traffic in real-time!
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
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
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
	"sort"
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

type CertConfig struct {
	Organization      string
	CommonName        string
	ValidityYears     int
	AIAURLs           string
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

func sanitizeForConsole(data string) string {
	var result strings.Builder
	result.Grow(len(data))
	
	for _, r := range data {
		if r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		} else if r >= 32 && r < 127 {
			result.WriteRune(r)
		} else if r >= 128 {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	
	return result.String()
}

func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
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
	
	return nullCount > sampleSize/10 || controlCount > sampleSize*3/10
}

// ==================== MONITORING MODULE ====================

// TrafficEntry represents a captured HTTP request/response
type TrafficEntry struct {
	ID              int
	Timestamp       time.Time
	Method          string
	URL             string
	Host            string
	Path            string
	StatusCode      int
	StatusText      string
	RequestHeaders  map[string][]string
	ResponseHeaders map[string][]string
	RequestBody     string
	ResponseBody    string
	ContentType     string
	Duration        time.Duration
	TLSVersion      string
	ClientAddr      string
}

// TrafficStore holds all captured traffic with thread-safe access
type TrafficStore struct {
	sync.RWMutex
	entries    []TrafficEntry
	nextID     int
	maxEntries int
}

var trafficStore = &TrafficStore{
	entries:    make([]TrafficEntry, 0),
	nextID:     1,
	maxEntries: 1000,
}

func (ts *TrafficStore) AddEntry(entry TrafficEntry) {
	ts.Lock()
	defer ts.Unlock()
	
	entry.ID = ts.nextID
	ts.nextID++
	
	ts.entries = append(ts.entries, entry)
	
	if len(ts.entries) > ts.maxEntries {
		ts.entries = ts.entries[len(ts.entries)-ts.maxEntries:]
	}
}

func (ts *TrafficStore) GetEntries() []TrafficEntry {
	ts.RLock()
	defer ts.RUnlock()
	
	result := make([]TrafficEntry, len(ts.entries))
	for i, entry := range ts.entries {
		result[len(ts.entries)-1-i] = entry
	}
	
	return result
}

func (ts *TrafficStore) GetEntry(id int) *TrafficEntry {
	ts.RLock()
	defer ts.RUnlock()
	
	for _, entry := range ts.entries {
		if entry.ID == id {
			return &entry
		}
	}
	return nil
}

func (ts *TrafficStore) Clear() {
	ts.Lock()
	defer ts.Unlock()
	
	ts.entries = make([]TrafficEntry, 0)
}

// MonitoringModule captures traffic for the web interface
type MonitoringModule struct {
	captureRequestBodies  bool
	captureResponseBodies bool
	maxBodySize           int
}

func NewMonitoringModule() *MonitoringModule {
	return &MonitoringModule{
		captureRequestBodies:  true,
		captureResponseBodies: true,
		maxBodySize:           10240,
	}
}

func (m *MonitoringModule) Name() string {
	return "Monitor"
}

func (m *MonitoringModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *MonitoringModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *MonitoringModule) ProcessResponse(resp *http.Response) error {
	startTime := time.Now()
	
	entry := TrafficEntry{
		Timestamp:       startTime,
		Method:          resp.Request.Method,
		URL:             resp.Request.URL.String(),
		Host:            resp.Request.URL.Hostname(),
		Path:            resp.Request.URL.Path,
		StatusCode:      resp.StatusCode,
		StatusText:      resp.Status,
		RequestHeaders:  cloneHeaders(resp.Request.Header),
		ResponseHeaders: cloneHeaders(resp.Header),
		ContentType:     resp.Header.Get("Content-Type"),
		ClientAddr:      "",
	}
	
	if m.captureResponseBodies && resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			
			if !isBinaryContent(bodyBytes) && len(bodyBytes) <= m.maxBodySize {
				entry.ResponseBody = string(bodyBytes)
			} else if len(bodyBytes) > m.maxBodySize {
				entry.ResponseBody = string(bodyBytes[:m.maxBodySize]) + 
					fmt.Sprintf("... [truncated, %d more bytes]", len(bodyBytes)-m.maxBodySize)
			}
		}
	}
	
	entry.Duration = time.Since(startTime)
	
	trafficStore.AddEntry(entry)
	
	return nil
}

func cloneHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string)
	for k, v := range h {
		clone[k] = append([]string{}, v...)
	}
	return clone
}

// ==================== MONITOR WEB SERVER ====================

func StartMonitorServer(port int) {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/entries", handleAPIEntries)
	http.HandleFunc("/api/entry/", handleAPIEntry)
	http.HandleFunc("/api/clear", handleAPIClear)
	http.HandleFunc("/api/stats", handleAPIStats)
	
	addr := fmt.Sprintf(":%d", port)
	log.Printf("[MONITOR] Starting monitor server on http://localhost%s", addr)
	
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("[MONITOR] Server error: %v", err)
		}
	}()
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	htmlPage := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Proxy Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            color: white;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .stats {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .stat-box {
            background: rgba(255,255,255,0.1);
            padding: 12px 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }
        
        .stat-box .label {
            font-size: 12px;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-box .value {
            font-size: 24px;
            font-weight: bold;
            margin-top: 5px;
        }
        
        .controls {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .controls input[type="text"] {
            flex: 1;
            min-width: 250px;
            padding: 10px 15px;
            border: 2px solid #3a3a3a;
            border-radius: 8px;
            background: #1a1a1a;
            color: #e0e0e0;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .controls input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .controls button {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            background: #667eea;
            color: white;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .controls button:hover {
            background: #5568d3;
            transform: translateY(-1px);
        }
        
        .controls button.danger {
            background: #e74c3c;
        }
        
        .controls button.danger:hover {
            background: #c0392b;
        }
        
        .controls label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            user-select: none;
        }
        
        .table-container {
            background: #2a2a2a;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #3a3a3a;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #b0b0b0;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
            border-bottom: 2px solid #4a4a4a;
        }
        
        tbody tr {
            border-bottom: 1px solid #3a3a3a;
            transition: background 0.2s;
            cursor: pointer;
        }
        
        tbody tr:hover {
            background: #333333;
        }
        
        td {
            padding: 15px;
            font-size: 14px;
        }
        
        .method {
            font-weight: bold;
            padding: 4px 10px;
            border-radius: 6px;
            display: inline-block;
            font-size: 12px;
        }
        
        .method.GET { background: #27ae60; color: white; }
        .method.POST { background: #f39c12; color: white; }
        .method.PUT { background: #3498db; color: white; }
        .method.DELETE { background: #e74c3c; color: white; }
        .method.PATCH { background: #9b59b6; color: white; }
        
        .status {
            font-weight: bold;
            padding: 4px 10px;
            border-radius: 6px;
            display: inline-block;
            font-size: 12px;
        }
        
        .status.success { background: #27ae60; color: white; }
        .status.redirect { background: #3498db; color: white; }
        .status.client-error { background: #e67e22; color: white; }
        .status.server-error { background: #e74c3c; color: white; }
        
        .url {
            color: #6eb5ff;
            word-break: break-all;
        }
        
        .timestamp {
            color: #95a5a6;
            font-size: 12px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            padding: 20px;
            overflow-y: auto;
        }
        
        .modal-content {
            background: #2a2a2a;
            max-width: 1200px;
            margin: 40px auto;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #3a3a3a;
        }
        
        .modal-header h2 {
            color: #667eea;
        }
        
        .close-btn {
            background: none;
            border: none;
            color: #95a5a6;
            font-size: 32px;
            cursor: pointer;
            transition: color 0.3s;
        }
        
        .close-btn:hover {
            color: #e74c3c;
        }
        
        .detail-section {
            margin-bottom: 25px;
        }
        
        .detail-section h3 {
            color: #667eea;
            margin-bottom: 12px;
            font-size: 18px;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
            background: #1a1a1a;
            padding: 15px;
            border-radius: 8px;
        }
        
        .detail-grid .label {
            color: #95a5a6;
            font-weight: 600;
        }
        
        .detail-grid .value {
            color: #e0e0e0;
        }
        
        .headers-list {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .header-item {
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid #3a3a3a;
        }
        
        .header-item:last-child {
            border-bottom: none;
        }
        
        .header-name {
            color: #f39c12;
            font-weight: bold;
        }
        
        .header-value {
            color: #95a5a6;
            margin-left: 10px;
        }
        
        .body-content {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #95a5a6;
        }
        
        .empty-state-icon {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        @media (max-width: 768px) {
            .controls {
                flex-direction: column;
            }
            
            .controls input[type="text"] {
                width: 100%;
            }
            
            .stats {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 TLS Proxy Monitor</h1>
        <div class="stats">
            <div class="stat-box">
                <div class="label">Total Requests</div>
                <div class="value" id="totalRequests">0</div>
            </div>
            <div class="stat-box">
                <div class="label">Success Rate</div>
                <div class="value" id="successRate">0%</div>
            </div>
            <div class="stat-box">
                <div class="label">Avg Response Time</div>
                <div class="value" id="avgTime">0ms</div>
            </div>
        </div>
    </div>
    
    <div class="controls">
        <input type="text" id="searchBox" placeholder="🔍 Search by URL, host, method, or status...">
        <label>
            <input type="checkbox" id="autoRefresh" checked>
            Auto-refresh (2s)
        </label>
        <button onclick="loadEntries()">🔄 Refresh Now</button>
        <button class="danger" onclick="clearEntries()">🗑️ Clear All</button>
    </div>
    
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody id="trafficTable">
                <tr>
                    <td colspan="7" class="empty-state">
                        <div class="empty-state-icon">📡</div>
                        <div>No traffic captured yet. Make some requests through the proxy!</div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    
    <div id="detailModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2>Request Details</h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>
    
    <script>
        let searchTerm = '';
        let autoRefreshInterval = null;
        
        document.getElementById('searchBox').addEventListener('input', (e) => {
            searchTerm = e.target.value.toLowerCase();
            loadEntries();
        });
        
        document.getElementById('autoRefresh').addEventListener('change', (e) => {
            if (e.target.checked) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
        
        function startAutoRefresh() {
            if (!autoRefreshInterval) {
                autoRefreshInterval = setInterval(loadEntries, 2000);
            }
        }
        
        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        }
        
        async function loadEntries() {
            try {
                const response = await fetch('/api/entries');
                const entries = await response.json();
                
                const filtered = entries.filter(entry => {
                    if (!searchTerm) return true;
                    return entry.URL.toLowerCase().includes(searchTerm) ||
                           entry.Host.toLowerCase().includes(searchTerm) ||
                           entry.Method.toLowerCase().includes(searchTerm) ||
                           entry.StatusCode.toString().includes(searchTerm);
                });
                
                renderTable(filtered);
                updateStats(entries);
            } catch (error) {
                console.error('Failed to load entries:', error);
            }
        }
        
        function renderTable(entries) {
            const tbody = document.getElementById('trafficTable');
            
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="empty-state-icon">📡</div><div>No traffic captured yet. Make some requests through the proxy!</div></td></tr>';
                return;
            }
            
            tbody.innerHTML = entries.map(entry => {
                const time = new Date(entry.Timestamp).toLocaleTimeString();
                const statusClass = getStatusClass(entry.StatusCode);
                const duration = entry.Duration ? (entry.Duration / 1000000).toFixed(0) + 'ms' : '-';
                
                return '<tr onclick="showDetails(' + entry.ID + ')"><td class="timestamp">' + time + '</td><td><span class="method ' + entry.Method + '">' + entry.Method + '</span></td><td>' + escapeHtml(entry.Host) + '</td><td class="url">' + escapeHtml(entry.Path) + '</td><td><span class="status ' + statusClass + '">' + (entry.StatusCode || '-') + '</span></td><td>' + duration + '</td><td>' + (entry.ContentType || '-') + '</td></tr>';
            }).join('');
        }
        
        function getStatusClass(code) {
            if (code >= 200 && code < 300) return 'success';
            if (code >= 300 && code < 400) return 'redirect';
            if (code >= 400 && code < 500) return 'client-error';
            if (code >= 500) return 'server-error';
            return '';
        }
        
        async function updateStats(entries) {
            document.getElementById('totalRequests').textContent = entries.length;
            
            const successCount = entries.filter(e => e.StatusCode >= 200 && e.StatusCode < 300).length;
            const successRate = entries.length > 0 ? ((successCount / entries.length) * 100).toFixed(1) : 0;
            document.getElementById('successRate').textContent = successRate + '%';
            
            const avgDuration = entries.length > 0
                ? entries.reduce((sum, e) => sum + (e.Duration || 0), 0) / entries.length / 1000000
                : 0;
            document.getElementById('avgTime').textContent = avgDuration.toFixed(0) + 'ms';
        }
        
        async function showDetails(id) {
            try {
                const response = await fetch('/api/entry/' + id);
                const entry = await response.json();
                
                if (!entry) {
                    alert('Entry not found');
                    return;
                }
                
                const modalBody = document.getElementById('modalBody');
                let html = '<div class="detail-section"><h3>Request Information</h3><div class="detail-grid">';
                html += '<div class="label">Method:</div><div class="value"><span class="method ' + entry.Method + '">' + entry.Method + '</span></div>';
                html += '<div class="label">URL:</div><div class="value">' + escapeHtml(entry.URL) + '</div>';
                html += '<div class="label">Host:</div><div class="value">' + escapeHtml(entry.Host) + '</div>';
                html += '<div class="label">Path:</div><div class="value">' + escapeHtml(entry.Path) + '</div>';
                html += '<div class="label">Timestamp:</div><div class="value">' + new Date(entry.Timestamp).toLocaleString() + '</div>';
                html += '</div></div>';
                
                if (entry.StatusCode) {
                    html += '<div class="detail-section"><h3>Response Information</h3><div class="detail-grid">';
                    html += '<div class="label">Status:</div><div class="value"><span class="status ' + getStatusClass(entry.StatusCode) + '">' + entry.StatusCode + ' ' + escapeHtml(entry.StatusText) + '</span></div>';
                    html += '<div class="label">Content-Type:</div><div class="value">' + escapeHtml(entry.ContentType) + '</div>';
                    html += '<div class="label">Duration:</div><div class="value">' + (entry.Duration ? (entry.Duration / 1000000).toFixed(2) + 'ms' : 'N/A') + '</div>';
                    html += '</div></div>';
                }
                
                html += '<div class="detail-section"><h3>Request Headers</h3><div class="headers-list">' + formatHeaders(entry.RequestHeaders) + '</div></div>';
                
                if (entry.ResponseHeaders) {
                    html += '<div class="detail-section"><h3>Response Headers</h3><div class="headers-list">' + formatHeaders(entry.ResponseHeaders) + '</div></div>';
                }
                
                if (entry.ResponseBody) {
                    html += '<div class="detail-section"><h3>Response Body</h3><div class="body-content">' + escapeHtml(entry.ResponseBody) + '</div></div>';
                }
                
                modalBody.innerHTML = html;
                document.getElementById('detailModal').style.display = 'block';
            } catch (error) {
                console.error('Failed to load entry details:', error);
                alert('Failed to load entry details');
            }
        }
        
        function formatHeaders(headers) {
            if (!headers) return '<div style="color: #95a5a6;">No headers</div>';
            
            return Object.entries(headers).map(([name, values]) => {
                const valueStr = Array.isArray(values) ? values.join(', ') : values;
                return '<div class="header-item"><span class="header-name">' + escapeHtml(name) + ':</span><span class="header-value">' + escapeHtml(valueStr) + '</span></div>';
            }).join('');
        }
        
        function closeModal(event) {
            if (!event || event.target.id === 'detailModal') {
                document.getElementById('detailModal').style.display = 'none';
            }
        }
        
        async function clearEntries() {
            if (!confirm('Are you sure you want to clear all captured traffic?')) {
                return;
            }
            
            try {
                await fetch('/api/clear', { method: 'POST' });
                loadEntries();
            } catch (error) {
                console.error('Failed to clear entries:', error);
                alert('Failed to clear entries');
            }
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        startAutoRefresh();
        loadEntries();
    </script>
</body>
</html>`
	
	fmt.Fprint(w, htmlPage)
}

func handleAPIEntries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := trafficStore.GetEntries()
	json.NewEncoder(w).Encode(entries)
}

func handleAPIEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	idStr := strings.TrimPrefix(r.URL.Path, "/api/entry/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)
	
	entry := trafficStore.GetEntry(id)
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	
	json.NewEncoder(w).Encode(entry)
}

func handleAPIClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	trafficStore.Clear()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	entries := trafficStore.GetEntries()
	
	stats := map[string]interface{}{
		"total":       len(entries),
		"methods":     countByMethod(entries),
		"statusCodes": countByStatusCode(entries),
		"hosts":       countByHost(entries),
	}
	
	json.NewEncoder(w).Encode(stats)
}

func countByMethod(entries []TrafficEntry) map[string]int {
	counts := make(map[string]int)
	for _, entry := range entries {
		counts[entry.Method]++
	}
	return counts
}

func countByStatusCode(entries []TrafficEntry) map[int]int {
	counts := make(map[int]int)
	for _, entry := range entries {
		if entry.StatusCode > 0 {
			counts[entry.StatusCode]++
		}
	}
	return counts
}

func countByHost(entries []TrafficEntry) []map[string]interface{} {
	counts := make(map[string]int)
	for _, entry := range entries {
		counts[entry.Host]++
	}
	
	type hostCount struct {
		host  string
		count int
	}
	var hosts []hostCount
	for host, count := range counts {
		hosts = append(hosts, hostCount{host, count})
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].count > hosts[j].count
	})
	
	result := make([]map[string]interface{}, 0)
	for i, hc := range hosts {
		if i >= 10 {
			break
		}
		result = append(result, map[string]interface{}{
			"host":  hc.host,
			"count": hc.count,
		})
	}
	
	return result
}

// ==================== BUILT-IN LOGGING MODULES ====================

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

type OAuthModule struct{}

func (m *OAuthModule) Name() string {
	return "OAuth"
}

func (m *OAuthModule) ShouldLog(req *http.Request) bool {
	url := req.URL.String()
	path := strings.ToLower(req.URL.Path)
	
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
	for key, value := range m.AddHeaders {
		req.Header.Set(key, value)
		log.Printf("[RequestModifier] Added header: %s: %s", key, value)
	}
	
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
	for key, value := range m.AddHeaders {
		resp.Header.Set(key, value)
		log.Printf("[ResponseModifier] Added header: %s: %s", key, value)
	}
	
	for _, key := range m.RemoveHeaders {
		if resp.Header.Get(key) != "" {
			resp.Header.Del(key)
			log.Printf("[ResponseModifier] Removed header: %s", key)
		}
	}
	
	return nil
}

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

type StringReplacementModule struct {
	Replacements map[string]string
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

	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		isText := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") ||
			strings.Contains(contentType, "application/x-www-form-urlencoded") ||
			strings.Contains(contentType, "application/javascript")
		
		if !isText {
			return nil
		}
	}

	var reader io.Reader = req.Body
	encoding := req.Header.Get("Content-Encoding")
	
	if encoding == "gzip" {
		gzipReader, err := gzip.NewReader(req.Body)
		if err != nil {
			log.Printf("[StringReplacement] Warning: Failed to decompress gzip request: %v", err)
			reader = req.Body
		} else {
			reader = gzipReader
			defer gzipReader.Close()
		}
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	req.Body.Close()

	bodyStr := string(bodyBytes)
	for old, new := range m.Replacements {
		if strings.Contains(bodyStr, old) {
			count := strings.Count(bodyStr, old)
			bodyStr = strings.ReplaceAll(bodyStr, old, new)
			log.Printf("[StringReplacement] Request: Replaced '%s' with '%s' (%d occurrences)", old, new, count)
		}
	}

	req.Body = io.NopCloser(bytes.NewBufferString(bodyStr))
	req.ContentLength = int64(len(bodyStr))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
	
	if encoding != "" {
		req.Header.Del("Content-Encoding")
		log.Printf("[StringReplacement] Removed Content-Encoding: %s (returning uncompressed)", encoding)
	}

	return nil
}

func (m *StringReplacementModule) ProcessResponse(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		isText := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") ||
			strings.Contains(contentType, "application/javascript")
		
		if !isText {
			return nil
		}
	}

	encoding := resp.Header.Get("Content-Encoding")
	
	if encoding == "br" || encoding == "zstd" || encoding == "deflate" {
		log.Printf("[StringReplacement] Warning: Skipping response with unsupported compression: %s", encoding)
		return nil
	}
	
	var reader io.Reader = resp.Body
	
	if encoding == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("[StringReplacement] Warning: Failed to decompress gzip response: %v", err)
			reader = resp.Body
		} else {
			reader = gzipReader
			defer gzipReader.Close()
		}
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	resp.Body.Close()

	bodyStr := string(bodyBytes)
	for old, new := range m.Replacements {
		if strings.Contains(bodyStr, old) {
			count := strings.Count(bodyStr, old)
			bodyStr = strings.ReplaceAll(bodyStr, old, new)
			log.Printf("[StringReplacement] Response: Replaced '%s' with '%s' (%d occurrences)", old, new, count)
		}
	}

	resp.Body = io.NopCloser(bytes.NewBufferString(bodyStr))
	resp.ContentLength = int64(len(bodyStr))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
	
	if encoding != "" && encoding != "br" && encoding != "zstd" && encoding != "deflate" {
		resp.Header.Del("Content-Encoding")
		log.Printf("[StringReplacement] Removed Content-Encoding: %s (returning uncompressed)", encoding)
	}

	return nil
}

type ForceGzipModule struct{}

func (m *ForceGzipModule) Name() string {
	return "ForceGzip"
}

func (m *ForceGzipModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *ForceGzipModule) ProcessRequest(req *http.Request) error {
	acceptEncoding := req.Header.Get("Accept-Encoding")
	
	if acceptEncoding == "" {
		return nil
	}
	
	encodings := strings.Split(acceptEncoding, ",")
	var supported []string
	
	for _, enc := range encodings {
		enc = strings.TrimSpace(enc)
		if strings.Contains(enc, "gzip") || enc == "identity" {
			supported = append(supported, enc)
		}
	}
	
	if len(supported) == 0 {
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

// ==================== MAIN FUNCTION ====================

func main() {
	port := flag.Int("port", 8080, "Proxy port")
	cleanup := flag.Bool("cleanup", false, "Remove CA certificates and exit")
	certDir := flag.String("certdir", ".", "Certificate directory")
	skipInstall := flag.Bool("skip-install", false, "Skip automatic certificate installation")
	configFile := flag.String("config", "proxy-config.ini", "Configuration file path")
	monitorPort := flag.Int("monitor-port", 4040, "Monitor web interface port")
	flag.Parse()

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

	initializeModules()

	// Start monitoring web interface
	StartMonitorServer(*monitorPort)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %d", config.Port)
	log.Printf("Monitor interface: http://localhost:%d", *monitorPort)
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
	
	// Register monitoring module FIRST to capture all traffic
	RegisterModule(NewMonitoringModule())
	
	// Default: Log all traffic
	RegisterModule(&AllTrafficModule{})
	
	// Uncomment to enable OAuth-only logging:
	// RegisterModule(&OAuthModule{})
	
	// Uncomment to filter by domain:
	// RegisterModule(&DomainFilterModule{
	// 	Domains: []string{"example.com", "api.example.com"},
	// })
	
	// Uncomment to filter by path:
	// RegisterModule(&PathFilterModule{
	// 	Paths: []string{"/api/", "/v1/"},
	// })
	
	// Uncomment to modify requests:
	// RegisterModule(&RequestModifierModule{
	// 	AddHeaders: map[string]string{
	// 		"X-Proxy-Debug": "true",
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
	
	// Uncomment to replace strings:
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
		
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

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

	if len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
		log.Printf("CA CRL Distribution Points: %v", certConfig.CRLDistPoints)
	}

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
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
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

func forwardRequest(req *http.Request) (*http.Response, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
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
	
	executeModulesResponse(resp)
	
	return resp, nil
}

func logRequest(req *http.Request, config *ProxyConfig) {
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
				maxBodySize := 10240
				bodyStr := string(bodyBytes)
				if len(bodyBytes) > maxBodySize {
					bodyStr = string(bodyBytes[:maxBodySize]) + fmt.Sprintf("... [truncated, %d more bytes]", len(bodyBytes)-maxBodySize)
				}
				logEntry = logEntry + fmt.Sprintf("Body: %s\n", bodyStr)
			}
		}
	}

	consoleEntry := sanitizeForConsole(logEntry)
	fmt.Print(consoleEntry)

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

func generateCertForHost(hostname string) *tls.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	sanDNSNames := []string{hostname}
	sanIPAddresses := []net.IP{}

	for _, san := range certConfig.DefaultSANs {
		if ip := net.ParseIP(san); ip != nil {
			sanIPAddresses = append(sanIPAddresses, ip)
		} else {
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

	if ip := net.ParseIP(hostname); ip != nil {
		sanIPAddresses = append(sanIPAddresses, ip)
	}

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

	if certConfig.IncludeCDPInHosts && len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
	}

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
	_, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found in PATH - manual installation required")
	}

	log.Printf("Installing certificate to Windows trust store...")
	log.Printf("Running: certutil -addstore -user Root \"%s\"", certPath)
	
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	output, err := cmd.CombinedOutput()
	
	if len(output) > 0 {
		log.Printf("certutil output: %s", string(output))
	}
	
	if err != nil {
		return fmt.Errorf("certutil failed: %v - %s", err, string(output))
	}
	
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
	
	input, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	
	cmd := exec.Command("sudo", "tee", destPath)
	cmd.Stdin = bytes.NewReader(input)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}
	
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
