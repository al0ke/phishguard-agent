'use client'

import { useState } from 'react'

interface TalosResult {
  target: string
  isIP: boolean
  resolvedIp: string | null
  domain: string | null
  reputation: string
  severity: 'clean' | 'suspicious' | 'malicious'
  severityColor: string
  signals: string[]
  blocklisted: boolean
  blocklistSource: string
  domainAge: string | null
  domainAgeDays: number | null
  recentlyRegistered: boolean
  ipInfo: {
    country: string | null
    countryCode: string | null
    region: string | null
    city: string | null
    isp: string | null
    org: string | null
    as: string | null
    asname: string | null
    lat: number | null
    lon: number | null
    reverse: string | null
  } | null
  talosNote: string
  error?: string
}

export default function TalosLookup() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<TalosResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!input.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/talos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: input.trim() }),
      })
      const data = await res.json()
      if (data.error) {
        setError(data.error)
      } else {
        setResult(data)
      }
    } catch {
      setError('Failed to complete reputation lookup.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
        <p className="text-xs text-gray-400 mb-3">
          Talos Intelligence reputation lookup. Checks IP/domain against Talos, Spamhaus, and EmergingThreats blocklists,
          plus RDAP domain registration data and geolocation intelligence.
        </p>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="Enter IP or domain (e.g. 8.8.8.8 or suspicious-site.com)"
            className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          />
          <button
            onClick={handleScan}
            disabled={loading || !input.trim()}
            className="px-6 py-2.5 bg-[#00ff88] text-black font-bold rounded-lg disabled:opacity-50 hover:bg-[#00cc70] transition-colors text-sm uppercase tracking-wider"
          >
            {loading ? 'Scanning...' : 'Query'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-sm text-gray-400">Checking blocklists, WHOIS, and geolocation...</p>
        </div>
      )}

      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
          <p className="text-[#ff3366] text-sm">{error}</p>
        </div>
      )}

      {result && !result.error && (
        <div className="space-y-3">
          {/* Verdict Card */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Reputation</p>
                <p className="text-2xl font-bold" style={{ color: result.severityColor }}>
                  {result.reputation}
                </p>
              </div>
              <div className="text-right">
                <span className={`text-[10px] px-2 py-0.5 rounded ${result.isIP ? 'bg-[#00ccff]/20 text-[#00ccff]' : 'bg-[#ffcc00]/20 text-[#ffcc00]'}`}>
                  {result.isIP ? 'IP' : 'DOMAIN'}
                </span>
                <p className="text-sm font-mono text-[#00ccff] mt-1">{result.target}</p>
              </div>
            </div>
            {result.resolvedIp && !result.isIP && (
              <p className="text-xs text-gray-500 mt-2">Resolved IP: <span className="font-mono text-white">{result.resolvedIp}</span></p>
            )}
          </div>

          {/* Blocklist Status */}
          <div className={`rounded-lg p-4 border ${result.blocklisted ? 'bg-[#ff3366]/10 border-[#ff3366]/50' : 'bg-[#00ff88]/10 border-[#00ff88]/30'}`}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Blocklist Status</p>
                <p className={`text-lg font-bold ${result.blocklisted ? 'text-[#ff3366]' : 'text-[#00ff88]'}`}>
                  {result.blocklisted ? 'LISTED' : 'NOT LISTED'}
                </p>
              </div>
              <p className="text-[10px] text-gray-500 text-right max-w-[180px]">{result.blocklistSource}</p>
            </div>
          </div>

          {/* Risk Signals */}
          {result.signals.length > 0 && (
            <div className="bg-[#111119] border border-[#ffcc00]/30 rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Risk Signals ({result.signals.length})</p>
              <div className="space-y-1.5">
                {result.signals.map((signal, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <span className="text-[#ffcc00] text-xs mt-0.5">⚠</span>
                    <p className="text-xs text-gray-300">{signal}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Domain Info */}
          {(result.domainAge || result.recentlyRegistered) && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Domain Registration</p>
              <div className="grid grid-cols-2 gap-3">
                {result.domainAge && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Domain Age</p>
                    <p className={`text-sm ${result.recentlyRegistered ? 'text-[#ffcc00]' : 'text-white'}`}>{result.domainAge}</p>
                  </div>
                )}
                {result.recentlyRegistered && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Flag</p>
                    <p className="text-sm text-[#ffcc00]">Recently Registered</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* IP Infrastructure */}
          {result.ipInfo && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">IP Infrastructure</p>
              <div className="grid grid-cols-2 gap-3">
                {result.ipInfo.country && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Country</p>
                    <p className="text-sm text-white">{result.ipInfo.country}</p>
                  </div>
                )}
                {result.ipInfo.city && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">City</p>
                    <p className="text-sm text-white">{result.ipInfo.city}</p>
                  </div>
                )}
                {result.ipInfo.isp && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">ISP</p>
                    <p className="text-sm text-white">{result.ipInfo.isp}</p>
                  </div>
                )}
                {result.ipInfo.as && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">ASN</p>
                    <p className="text-sm text-white">{result.ipInfo.as}</p>
                  </div>
                )}
                {result.ipInfo.org && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Organization</p>
                    <p className="text-sm text-white">{result.ipInfo.org}</p>
                  </div>
                )}
                {result.ipInfo.reverse && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Reverse DNS</p>
                    <p className="text-sm font-mono text-[#00ccff]">{result.ipInfo.reverse}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Data Sources Note */}
          <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-3">
            <p className="text-[10px] text-gray-600">{result.talosNote}</p>
          </div>
        </div>
      )}
    </div>
  )
}