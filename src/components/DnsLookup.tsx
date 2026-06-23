'use client'

import { useState, useEffect } from 'react'
import { logAudit } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

export default function DnsLookup({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    if (prefill) {
      setDomain(prefill.replace(/^https?:\/\//, '').split('/')[0])
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const lookup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Lookup failed'); setLoading(false); return }
      setResult(data)
      await logAudit({ tool: 'DNS', target: domain.trim(), riskScore: 10, threatLevel: 'low', findings: ['DNS lookup completed'] })
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  const recordTypeColors: Record<string, string> = {
    A: 'text-[#00ff88] bg-[#00ff88]/10',
    MX: 'text-[#00ccff] bg-[#00ccff]/10',
    TXT: 'text-[#ff9900] bg-[#ff9900]/10',
    NS: 'text-[#cc99ff] bg-[#cc99ff]/10',
    AAAA: 'text-[#00ff88] bg-[#00ff88]/10',
    CNAME: 'text-[#ffcc00] bg-[#ffcc00]/10',
  }

  return (
    <div className="space-y-4">
      <form onSubmit={lookup} className="flex gap-2">
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        <button type="submit" disabled={!domain.trim() || loading} className="px-6 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? '...' : 'DNS'}
        </button>
      </form>

      {error && <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 text-red-400 text-sm">{error}</div>}

      {result && (
        <div className="space-y-3">
          {/* Summary */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <div className="grid grid-cols-3 gap-2 text-center">
              {['hasA', 'hasAAAA', 'hasMX', 'hasSPF', 'hasDMARC'].map((key) => {
                const summary = result.summary as Record<string, unknown>
                return (
                  <div key={key}>
                    <p className="text-xs text-gray-400">{key.replace('has', '')}</p>
                    <p className={`text-sm font-bold ${summary[key] ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>
                      {summary[key] ? '✓' : '✗'}
                    </p>
                  </div>
                )
              })}
              <div>
                <p className="text-xs text-gray-400">Total</p>
                <p className="text-sm font-bold text-white">{String((result.summary as Record<string, unknown>).recordCount ?? '')}</p>
              </div>
            </div>
          </div>

          {/* SPF */}
          {result.spf ? (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">SPF Record</p>
              <p className="text-xs font-mono text-[#00ff88] break-all">{result.spf as string}</p>
            </div>
          ) : null}

          {/* DMARC */}
          {result.dmarc ? (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">DMARC Record</p>
              <p className="text-xs font-mono text-[#00ccff] break-all">{result.dmarc as string}</p>
            </div>
          ) : null}

          {/* Records by type */}
          {Object.entries(result.records || {}).map(([type, records]: [string, any]) => {
            if (!records || records.length === 0) return null
            return (
              <div key={type} className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-xs font-mono px-2 py-0.5 rounded ${recordTypeColors[type] || 'text-gray-400'}`}>{type}</span>
                  <span className="text-xs text-gray-500">{records.length} records</span>
                </div>
                <div className="space-y-1">
                  {records.map((r: any, i: number) => (
                    <div key={i} className="text-xs font-mono text-gray-300 break-all">
                      {r.data}
                      {r.ttl && <span className="text-gray-600 ml-2">TTL:{r.ttl}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}