'use client'

import { useState, useEffect } from 'react'

interface HistoryItem {
  type: string
  target: string
  timestamp: string
  riskScore?: number
  threatLevel?: string
  source?: 'local' | 'audit'
}

const tools = [
  { id: 'url', icon: '🔍', label: 'URL Scan', desc: 'Multi-engine threat analysis' },
  { id: 'domain', icon: '🌐', label: 'Domain', desc: 'WHOIS + brand + subdomains' },
  { id: 'hash', icon: '#', label: 'Hash', desc: 'VirusTotal file reputation' },
  { id: 'email', icon: '✉', label: 'Email', desc: 'SPF/DKIM/DMARC + triage' },
  { id: 'eml', icon: '📎', label: 'EML Parser', desc: 'Upload .eml for full analysis' },
  { id: 'dns', icon: 'DNS', label: 'DNS', desc: 'A/MX/TXT/NS/AAAA records' },
  { id: 'whois', icon: '📋', label: 'WHOIS', desc: 'RDAP + SSL cert data' },
  { id: 'ip', icon: '🌐', label: 'IP Lookup', desc: 'Ports, CVEs, tags, ASN' },
  { id: 'qr', icon: '📷', label: 'QR Code', desc: 'Decode + analyze destination' },
  { id: 'redirect', icon: '↗', label: 'Redirect', desc: 'Trace redirect chains + headers' },
  { id: 'bulk', icon: '⚡', label: 'Bulk Scan', desc: 'Scan multiple IOCs at once' },
  { id: 'sanitize', icon: '🛡', label: 'Sanitize', desc: 'URL defang/refang' },
  { id: 'screenshot', icon: '📸', label: 'Screenshot', desc: 'Capture URL as evidence' },
]

function mergeActivity(local: HistoryItem[], audit: HistoryItem[]): HistoryItem[] {
  const combined = [...audit, ...local]
  const seen = new Set<string>()
  const merged: HistoryItem[] = []

  for (const item of combined) {
    const key = `${item.type}:${item.target}:${item.timestamp.slice(0, 16)}`
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(item)
  }

  return merged
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 12)
}

export default function Overview({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [auditError, setAuditError] = useState<string | null>(null)

  useEffect(() => {
    let local: HistoryItem[] = []
    const raw = localStorage.getItem('threatAnalyzer_history')
    if (raw) {
      try {
        local = JSON.parse(raw).map((item: HistoryItem) => ({ ...item, source: 'local' as const }))
      } catch { /* ignore */ }
    }

    fetch('/api/audit?limit=25')
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          setAuditError(data.error)
          setHistory(local.slice(0, 12))
          return
        }
        const auditItems: HistoryItem[] = (data.entries || []).map((e: {
          tool: string
          target: string
          timestamp: string
          risk_score?: number
          threat_level?: string
        }) => ({
          type: e.tool,
          target: e.target,
          timestamp: e.timestamp,
          riskScore: e.risk_score,
          threatLevel: e.threat_level,
          source: 'audit' as const,
        }))
        setHistory(mergeActivity(local, auditItems))
      })
      .catch(() => {
        setHistory(local.slice(0, 12))
      })
  }, [])

  const stats = {
    total: history.length,
    threats: history.filter(h => h.threatLevel === 'critical' || h.threatLevel === 'high').length,
    medium: history.filter(h => h.threatLevel === 'medium').length,
    clean: history.filter(h => h.threatLevel === 'low' || h.threatLevel === 'clean' || h.threatLevel === 'safe').length,
  }

  return (
    <div className="space-y-4 max-w-3xl mx-auto">
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-xl p-4 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide">Total Scans</p>
          <p className="text-3xl font-bold text-white">{stats.total}</p>
        </div>
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/30 rounded-xl p-4 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide">Threats</p>
          <p className="text-3xl font-bold text-[#ff3366]">{stats.threats}</p>
        </div>
        <div className="bg-[#ffcc00]/10 border border-[#ffcc00]/30 rounded-xl p-4 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide">Medium</p>
          <p className="text-3xl font-bold text-[#ffcc00]">{stats.medium}</p>
        </div>
        <div className="bg-[#00ff88]/10 border border-[#00ff88]/30 rounded-xl p-4 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide">Clean</p>
          <p className="text-3xl font-bold text-[#00ff88]">{stats.clean}</p>
        </div>
      </div>

      <div className="bg-[#111119] border border-[#1a1a2e] rounded-xl p-4">
        <h2 className="text-xs font-bold text-[#00ff88] uppercase tracking-widest mb-3">Tools</h2>
        <div className="grid grid-cols-3 gap-2">
          {tools.map(tool => (
            <button
              key={tool.id}
              onClick={() => onNavigate(tool.id)}
              className="flex items-center gap-2.5 p-3 rounded-lg bg-[#0a0a0f] border border-[#1a1a2e] hover:border-[#00ff88]/40 hover:bg-[#00ff88]/5 transition-all text-left"
            >
              <span className="text-lg w-8 text-center">{tool.icon}</span>
              <div className="min-w-0">
                <p className="text-xs font-bold text-white truncate">{tool.label}</p>
                <p className="text-[10px] text-gray-500 truncate">{tool.desc}</p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {history.length > 0 && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-bold text-[#00ff88] uppercase tracking-widest">Recent Activity</h2>
            <span className="text-[10px] text-gray-600">local + audit log</span>
          </div>
          <div className="space-y-1.5">
            {history.map((item, i) => (
              <div key={i} className="flex items-center justify-between text-xs border-b border-[#1a1a2e] last:border-0 pb-1.5 mb-1.5 last:pb-0 last:mb-0">
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <span className="text-gray-500 font-mono w-16 flex-shrink-0">{item.type}</span>
                  <span className="font-mono text-white truncate">{item.target}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                  {item.riskScore !== undefined && item.riskScore !== null && (
                    <span className={`font-bold ${item.riskScore >= 70 ? 'text-[#ff3366]' : item.riskScore >= 40 ? 'text-[#ffcc00]' : 'text-[#00ff88]'}`}>
                      {item.riskScore}
                    </span>
                  )}
                  <span className="text-gray-600 text-[10px]">
                    {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {history.length === 0 && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-xl p-6 text-center">
          <p className="text-sm text-gray-400">No analysis yet. Pick a tool above to start.</p>
          {auditError && (
            <p className="text-xs text-gray-600 mt-2">Audit log unavailable — showing local activity only when scans run.</p>
          )}
        </div>
      )}
    </div>
  )
}
