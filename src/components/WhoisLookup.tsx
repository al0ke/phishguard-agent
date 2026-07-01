'use client'

import { useState, useEffect } from 'react'
import { logAudit } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

interface WhoisRegistrant {
  name?: string
  org?: string
  country?: string
  nameservers?: string[]
}

interface WhoisCert {
  issued: string | null
  expiry: string | null
  issuer: string | null
}

interface WhoisResult {
  domain: string
  registrar: string | null
  created: string | null
  updated: string | null
  expires: string | null
  registrant: WhoisRegistrant
  nameservers: string[]
  cert_count: number
  recent_certs: WhoisCert[]
  rdap_url: string | null
  rdap_found: boolean
  error?: string
}

export default function WhoisLookup({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<WhoisResult | null>(null)

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
      const res = await fetch('/api/whois', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Lookup failed'); setLoading(false); return }
      setResult(data)
      await logAudit({ tool: 'WHOIS', target: domain.trim(), riskScore: 15, threatLevel: 'low', findings: ['WHOIS lookup completed'] })
    } catch {
      setError('Network error')
    }
    setLoading(false)
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
        <button
          type="submit"
          disabled={!domain.trim() || loading}
          className="px-6 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50"
        >
          {loading ? '...' : 'WHOIS'}
        </button>
      </form>

      {loading && <LoadingState message="Querying RDAP and certificate transparency logs..." />}

      {error && <ErrorState message={error} />}

      {result && !result.error && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-bold text-[#00ff88] uppercase">WHOIS</span>
            {result.cert_count !== undefined && <span className="text-xs text-gray-400">{result.cert_count} SSL certs</span>}
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            {result.registrar && <>
              <span className="text-gray-400">Registrar</span>
              <span className="text-white font-mono text-xs">{result.registrar}</span>
            </>}
            {result.created && <>
              <span className="text-gray-400">Created</span>
              <span className="text-white font-mono text-xs">{new Date(result.created).toLocaleDateString()}</span>
            </>}
            {result.updated && <>
              <span className="text-gray-400">Updated</span>
              <span className="text-white font-mono text-xs">{new Date(result.updated).toLocaleDateString()}</span>
            </>}
            {result.expires && <>
              <span className="text-gray-400">Expires</span>
              <span className="text-white font-mono text-xs">{new Date(result.expires).toLocaleDateString()}</span>
            </>}
            {result.registrant?.country && <>
              <span className="text-gray-400">Country</span>
              <span className="text-white text-xs">{result.registrant.country}</span>
            </>}
            {result.registrant?.org && <>
              <span className="text-gray-400">Org</span>
              <span className="text-white text-xs">{result.registrant.org}</span>
            </>}
          </div>

          {result.nameservers?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-gray-400 mb-1 uppercase tracking-wide">Nameservers</p>
              <div className="flex flex-col gap-0.5">
                {result.nameservers.map((ns: string) => (
                  <span key={ns} className="text-xs font-mono text-[#00ccff]">{ns}</span>
                ))}
              </div>
            </div>
          )}

          {result.recent_certs?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-gray-400 mb-1 uppercase tracking-wide">Recent SSL</p>
              {result.recent_certs.map((c, i) => (
                <div key={i} className="text-xs font-mono text-gray-400">
                  {c.issuer?.slice(0,40) || 'Unknown'} | {c.issued ? new Date(c.issued).toLocaleDateString() : '?'} → {c.expiry ? new Date(c.expiry).toLocaleDateString() : '?'}
                </div>
              ))}
            </div>
          )}

          {result.rdap_url && (
            <div className="mt-2">
              <a href={result.rdap_url} target="_blank" className="text-xs text-[#00ff88] underline">RDAP Reference →</a>
            </div>
          )}
        </div>
      )}

      {result?.error && <ErrorState message={result.error} />}

      {!loading && !error && !result && (
        <EmptyState icon="📋" title="No WHOIS lookup yet" description="Enter a domain to view registrar, registration dates, nameservers, and SSL certificate history" />
      )}
    </div>
  )
}
