'use client'

import { useState, useEffect } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

interface IpReputationResult {
  ip: string
  isValid: boolean
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
  reputation: 'malicious' | 'suspicious' | 'clean'
  flags: { proxy: boolean; hosting: boolean; mobile: boolean }
  location: {
    country: string | null
    countryCode: string | null
    region: string | null
    city: string | null
    lat: number | null
    lon: number | null
    timezone: string | null
  }
  network: {
    isp: string | null
    org: string | null
    asn: string | null
    asname: string | null
    reverseDns: string | null
  }
  signals: string[]
  source: string
}

const riskColors: Record<IpReputationResult['riskLevel'], string> = {
  critical: '#ff3366',
  high: '#ff6633',
  medium: '#ffcc00',
  low: '#00ccff',
  safe: '#00ff88',
}

export default function IpReputationCheck({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [ip, setIp] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<IpReputationResult | null>(null)

  useEffect(() => {
    if (prefill) {
      setIp(prefill.trim())
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const check = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ip.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/ip-reputation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip.trim() }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'IP reputation lookup failed')
        setLoading(false)
        return
      }
      setResult(data as IpReputationResult)

      await logAudit({
        tool: 'IP_REPUTATION',
        target: ip.trim(),
        riskScore: data.riskScore,
        threatLevel: data.riskLevel,
        findings: data.signals || [],
      })
      saveLastResult({
        type: 'IP_REPUTATION',
        target: ip.trim(),
        timestamp: new Date().toISOString(),
        riskScore: data.riskScore,
        threatLevel: data.riskLevel,
        findings: data.signals || [],
        recommendations: [
          data.flags?.proxy ? 'Traffic from proxy/VPN — treat with elevated scrutiny' : null,
          data.flags?.hosting ? 'Datacenter/hosting IP — unusual for genuine end-user traffic' : null,
          data.reputation === 'malicious' ? 'Block this IP at the network perimeter' : 'Continue monitoring',
        ].filter(Boolean) as string[],
        iocs: { ips: [ip.trim()], domains: [], urls: [], hashes: [] },
        raw: data,
      })
    } catch {
      setError('Network error — failed to reach IP reputation service')
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
        <p className="text-xs text-gray-400 mb-3">
          Checks an IP address against ip-api.com for geolocation, ASN/ISP data, and proxy/VPN/hosting
          signals to flag likely-abusive infrastructure.
        </p>
        <form onSubmit={check} className="flex gap-2">
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="Enter IP address (e.g. 45.33.32.156)"
            className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !ip.trim()}
            className="px-6 py-2.5 bg-[#00ff88] text-black font-bold rounded-lg disabled:opacity-50 hover:bg-[#00cc70] transition-colors text-sm uppercase tracking-wider"
          >
            {loading ? 'Checking...' : 'Check'}
          </button>
        </form>
      </div>

      {loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-sm text-gray-400">Querying IP reputation database...</p>
        </div>
      )}

      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
          <p className="text-[#ff3366] text-sm">{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-3">
          {/* Verdict Card */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Reputation</p>
                <p className="text-2xl font-bold" style={{ color: riskColors[result.riskLevel] }}>
                  {result.reputation.toUpperCase()}
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Risk Score</p>
                <p className="text-2xl font-bold" style={{ color: riskColors[result.riskLevel] }}>
                  {result.riskScore}<span className="text-sm text-gray-500">/100</span>
                </p>
              </div>
            </div>
            <p className="text-sm font-mono text-[#00ccff] mt-2">{result.ip}</p>
          </div>

          {/* Flags */}
          <div className="grid grid-cols-3 gap-2">
            {([
              { key: 'proxy', label: 'Proxy/VPN' },
              { key: 'hosting', label: 'Hosting/DC' },
              { key: 'mobile', label: 'Mobile' },
            ] as const).map(({ key, label }) => (
              <div
                key={key}
                className={`rounded-lg p-3 text-center border ${
                  result.flags[key] ? 'bg-[#ff3366]/10 border-[#ff3366]/40' : 'bg-[#111119] border-[#1a1a2e]'
                }`}
              >
                <p className="text-xs text-gray-400 uppercase tracking-wide">{label}</p>
                <p className={`text-sm font-bold mt-1 ${result.flags[key] ? 'text-[#ff3366]' : 'text-[#00ff88]'}`}>
                  {result.flags[key] ? 'YES' : 'NO'}
                </p>
              </div>
            ))}
          </div>

          {/* Risk Signals */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Signals ({result.signals.length})</p>
            <div className="space-y-1.5">
              {result.signals.map((signal, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="text-[#ffcc00] text-xs mt-0.5">⚠</span>
                  <p className="text-xs text-gray-300">{signal}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Location */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Location</p>
            <div className="grid grid-cols-2 gap-3">
              {result.location.country && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">Country</p>
                  <p className="text-sm text-white">{result.location.country}</p>
                </div>
              )}
              {result.location.city && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">City</p>
                  <p className="text-sm text-white">{result.location.city}</p>
                </div>
              )}
              {result.location.region && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">Region</p>
                  <p className="text-sm text-white">{result.location.region}</p>
                </div>
              )}
              {result.location.timezone && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">Timezone</p>
                  <p className="text-sm text-white">{result.location.timezone}</p>
                </div>
              )}
            </div>
          </div>

          {/* Network */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Network</p>
            <div className="grid grid-cols-2 gap-3">
              {result.network.isp && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">ISP</p>
                  <p className="text-sm text-white">{result.network.isp}</p>
                </div>
              )}
              {result.network.org && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">Organization</p>
                  <p className="text-sm text-white">{result.network.org}</p>
                </div>
              )}
              {result.network.asn && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">ASN</p>
                  <p className="text-sm text-white">{result.network.asn}</p>
                </div>
              )}
              {result.network.reverseDns && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase">Reverse DNS</p>
                  <p className="text-sm font-mono text-[#00ccff]">{result.network.reverseDns}</p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-3">
            <p className="text-[10px] text-gray-600">Data source: {result.source} (free tier, no API key required)</p>
          </div>
        </div>
      )}

      {!loading && !error && !result && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-8 text-center">
          <span className="text-3xl">🌍</span>
          <p className="text-sm text-gray-400 mt-2">Enter an IP address to check its abuse reputation</p>
          <p className="text-xs text-gray-600 mt-1">Detects proxy/VPN usage, hosting providers, and high-risk regions</p>
        </div>
      )}
    </div>
  )
}
