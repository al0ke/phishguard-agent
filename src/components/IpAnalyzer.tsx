'use client'

import { useState, useEffect } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

interface IpEnrichResult {
  type: 'ip'
  query: string
  ip: string
  ports: number[]
  hostnames: string[]
  tags: string[]
  cves: string[]
  country: string | null
  asn: string | null
  summary?: string | null
  message?: string
  error?: string
}

export default function IpAnalyzer({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [ip, setIp] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<IpEnrichResult | null>(null)

  useEffect(() => {
    if (prefill) {
      setIp(prefill.trim())
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ip.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: ip.trim(), type: 'ip' }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Lookup failed'); setLoading(false); return }
      setResult(data)
      const cves = data.cves as string[] | undefined
      const tags = data.tags as string[] | undefined
      const riskScore = cves?.length ? Math.min(50 + cves.length * 10, 100) : (tags?.length ?? 0) > 3 ? 60 : 20
      const threatLevel = cves?.length ? 'critical' : (tags?.length ?? 0) > 3 ? 'high' : 'low'
      await logAudit({ tool: 'IP', target: ip.trim(), riskScore, threatLevel, findings: tags || [] })
      saveLastResult({
        type: 'IP',
        target: ip.trim(),
        timestamp: new Date().toISOString(),
        riskScore,
        threatLevel,
        findings: [data.country ? `Country: ${data.country}` : null, data.asn ? `ASN: ${data.asn}` : null].filter(Boolean) as string[],
        recommendations: [cves?.length ? 'Known CVEs on host — investigate' : 'Review open ports and tags'],
        iocs: { ips: [ip.trim()], domains: (data.hostnames as string[]) || [], urls: [], hashes: [] },
        raw: data,
      })
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={analyze} className="flex gap-2">
        <input
          value={ip}
          onChange={e => setIp(e.target.value)}
          placeholder="8.8.8.8"
          className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        <button type="submit" disabled={!ip.trim() || loading} className="px-6 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? '...' : 'Lookup'}
        </button>
      </form>

      {loading && <LoadingState message="Querying Shodan InternetDB for open ports and CVEs..." />}

      {error && <ErrorState message={error} />}

      {result && (
        <div className="space-y-3">
          {/* Risk Badge */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3 flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400">IP ADDRESS</p>
              <p className="text-sm font-mono text-white">{result.ip || result.query}</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-gray-400">RISK</p>
              <p className={`text-sm font-bold ${result.cves?.length ? 'text-[#ff3366]' : result.tags?.length > 3 ? 'text-[#ffcc00]' : 'text-[#00ff88]'}`}>
                {result.cves?.length ? 'CRITICAL' : result.tags?.length > 3 ? 'HIGH' : 'LOW'}
              </p>
            </div>
          </div>

          {/* Geo + ASN */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Location & Network</p>
            <div className="grid grid-cols-2 gap-2 text-sm">
              {result.country && <><span className="text-gray-400">Country</span><span className="text-white">{result.country}</span></>}
              {result.asn && <><span className="text-gray-400">ASN</span><span className="text-white font-mono text-xs">{result.asn}</span></>}
            </div>
          </div>

          {/* Open Ports */}
          {result.ports?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Open Ports ({result.ports.length})</p>
              <div className="flex flex-wrap gap-1">
                {result.ports.map((p: number) => (
                  <span key={p} className={`text-xs font-mono px-2 py-0.5 rounded ${
                    [22, 3389, 445, 23, 21, 3306, 5432, 6379, 27017].includes(p)
                      ? 'text-[#ff3366] bg-[#ff3366]/10'
                      : 'text-[#00ccff] bg-[#00ccff]/10'
                  }`}>{p}</span>
                ))}
              </div>
            </div>
          )}

          {/* CVEs */}
          {result.cves?.length > 0 && (
            <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-3">
              <p className="text-xs text-[#ff3366] uppercase tracking-wide mb-2">⚠ Vulnerabilities ({result.cves.length})</p>
              <div className="space-y-0.5">
                {result.cves.map((c: string) => <div key={c} className="text-xs font-mono text-[#ff3366]">{c}</div>)}
              </div>
            </div>
          )}

          {/* Tags */}
          {result.tags?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Tags ({result.tags.length})</p>
              <div className="flex flex-wrap gap-1">
                {result.tags.map((t: string) => (
                  <span key={t} className={`text-xs font-mono px-2 py-0.5 rounded ${
                    ['malware', 'botnet', 'c2', 'scanner', 'exploit'].includes(t.toLowerCase())
                      ? 'text-[#ff3366] bg-[#ff3366]/10'
                      : 'text-[#ff9900] bg-[#ff9900]/10'
                  }`}>{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Hostnames */}
          {result.hostnames?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Hostnames ({result.hostnames.length})</p>
              <div className="space-y-0.5">
                {result.hostnames.map((h: string) => <div key={h} className="text-xs font-mono text-[#00ccff]">{h}</div>)}
              </div>
            </div>
          )}

          {!result.ports?.length && !result.cves?.length && !result.tags?.length && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 text-center">
              <p className="text-sm text-gray-400">No threat data found for this IP</p>
              <p className="text-xs text-gray-600 mt-1">This doesn&apos;t mean it&apos;s safe — just not in threat databases</p>
            </div>
          )}
        </div>
      )}

      {!loading && !error && !result && (
        <EmptyState icon="🌐" title="No IP lookup yet" description="Enter an IP address to check open ports, known CVEs, and Shodan classification tags" />
      )}
    </div>
  )
}