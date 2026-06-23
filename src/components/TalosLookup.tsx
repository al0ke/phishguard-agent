'use client'

import { useState } from 'react'

interface TalosResult {
  target: string
  isIP: boolean
  emailReputation: string
  emailScore: string | null
  emailSeverity: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  webReputation: string
  webScore: string | null
  webSeverity: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  category: string | null
  domainName: string | null
  country: string | null
  city: string | null
  organization: string | null
  isp: string | null
  asn: string | null
  error?: string
}

const severityColors: Record<string, string> = {
  clean: '#00ff88',
  suspicious: '#ffcc00',
  malicious: '#ff3366',
  unknown: '#888888',
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
      setError('Failed to query Talos Intelligence.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
        <p className="text-xs text-gray-400 mb-3">
          Query the Cisco Talos Reputation Center for IP and domain reputation data.
          Talos processes billions of web, email, firewall, and IPS events daily.
        </p>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="Enter IP address or domain (e.g. 8.8.8.8 or example.com)"
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
          <p className="text-sm text-gray-400">Querying Cisco Talos Reputation Center...</p>
        </div>
      )}

      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
          <p className="text-[#ff3366] text-sm">{error}</p>
        </div>
      )}

      {result && !result.error && (
        <div className="space-y-3">
          {/* Reputation Cards */}
          <div className="grid grid-cols-2 gap-3">
            {/* Email Reputation */}
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Email Reputation</p>
              <p className="text-lg font-bold" style={{ color: severityColors[result.emailSeverity] }}>
                {result.emailReputation}
              </p>
              {result.emailScore && (
                <p className="text-xs text-gray-500 mt-1">Score: {result.emailScore}</p>
              )}
            </div>

            {/* Web Reputation */}
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Web Reputation</p>
              <p className="text-lg font-bold" style={{ color: severityColors[result.webSeverity] }}>
                {result.webReputation}
              </p>
              {result.webScore && (
                <p className="text-xs text-gray-500 mt-1">Score: {result.webScore}</p>
              )}
            </div>
          </div>

          {/* Category */}
          {result.category && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Category</p>
              <p className="text-sm text-white">{result.category}</p>
            </div>
          )}

          {/* Location / Infrastructure */}
          {(result.country || result.isp || result.asn || result.organization) && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Infrastructure</p>
              <div className="grid grid-cols-2 gap-3">
                {result.country && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Country</p>
                    <p className="text-sm text-white">{result.country}</p>
                  </div>
                )}
                {result.city && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">City</p>
                    <p className="text-sm text-white">{result.city}</p>
                  </div>
                )}
                {result.isp && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">ISP</p>
                    <p className="text-sm text-white">{result.isp}</p>
                  </div>
                )}
                {result.asn && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">ASN</p>
                    <p className="text-sm text-white">{result.asn}</p>
                  </div>
                )}
                {result.organization && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Organization</p>
                    <p className="text-sm text-white">{result.organization}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Target Info */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-gray-500 uppercase">Target</p>
                <p className="text-sm font-mono text-[#00ccff]">{result.target}</p>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded ${result.isIP ? 'bg-[#00ccff]/20 text-[#00ccff]' : 'bg-[#ffcc00]/20 text-[#ffcc00]'}`}>
                {result.isIP ? 'IP' : 'DOMAIN'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}