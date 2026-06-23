'use client'

import { useState, useEffect } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

interface DomainResult {
  whois?: Record<string, any>
  osint?: Record<string, any>
  enrich?: Record<string, any>
  brand?: Record<string, any>
}

export default function DomainAnalyzer({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<DomainResult | null>(null)

  useEffect(() => {
    if (prefill) {
      setDomain(prefill.replace(/^https?:\/\//, '').split('/')[0])
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const saveReportData = async (r: DomainResult, target: string) => {
    if (typeof window !== 'undefined') {
      const findings: string[] = []
      if (r.whois?.registrar) findings.push(`Registrar: ${r.whois.registrar}`)
      if (r.whois?.created) findings.push(`Domain created: ${r.whois.created}`)
      if (r.brand?.isImpersonation) findings.push(`Brand impersonation: ${r.brand.matches[0]?.brand} (${r.brand.matches[0]?.similarity}% match)`)
      if (r.brand?.homoglyphsDetected) findings.push('Homoglyphs detected in domain name')
      if ((r.enrich as { subdomains?: unknown[] })?.subdomains?.length) findings.push(`${(r.enrich as { subdomains: unknown[] }).subdomains.length} subdomains discovered`)

      const riskScore = (r.brand as { isImpersonation?: boolean; matches?: { similarity?: number }[] })?.isImpersonation
        ? ((r.brand as { matches: { similarity?: number }[] }).matches[0]?.similarity ?? 0) >= 85 ? 90 : 60
        : 20
      const threatLevel = ((r.brand as { riskLevel?: string })?.riskLevel) || 'low'

      await logAudit({ tool: 'DOMAIN', target, riskScore, threatLevel, findings })

      saveLastResult({
        type: 'DOMAIN',
        target,
        timestamp: new Date().toISOString(),
        riskScore,
        threatLevel,
        findings,
        recommendations: [
          (r.brand as { isImpersonation?: boolean })?.isImpersonation ? 'Flag as brand impersonation — block domain' : null,
          (r.whois as { created?: string })?.created && new Date((r.whois as { created: string }).created) > new Date(Date.now() - 30 * 86400000) ? 'Newly registered domain — high risk' : null,
        ].filter(Boolean),
        iocs: { ips: [], domains: [target], urls: [], hashes: [] },
        raw: r,
      })
    }
  }

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    const [whoisRes, osintRes, enrichRes, brandRes] = await Promise.allSettled([
      fetch('/api/whois', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: domain.trim() }) }),
      fetch('/api/osint', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: domain.trim().startsWith('http') ? domain.trim() : `https://${domain.trim()}` }) }),
      fetch('/api/enrich', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: domain.trim(), type: 'domain' }) }),
      fetch('/api/brand', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: domain.trim() }) }),
    ])

    const r: DomainResult = {}
    if (whoisRes.status === 'fulfilled' && whoisRes.value.ok) r.whois = await whoisRes.value.json()
    if (osintRes.status === 'fulfilled' && osintRes.value.ok) r.osint = await osintRes.value.json()
    if (enrichRes.status === 'fulfilled' && enrichRes.value.ok) r.enrich = await enrichRes.value.json()
    if (brandRes.status === 'fulfilled' && brandRes.value.ok) r.brand = await brandRes.value.json()
    setResult(r)
    await saveReportData(r, domain.trim())
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={analyze} className="flex gap-2">
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        <button type="submit" disabled={!domain.trim() || loading} className="px-6 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? '...' : 'Lookup'}
        </button>
      </form>

      {error && <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 text-red-400 text-sm">{error}</div>}

      {loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 text-center">
          <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-xs text-gray-400">Running WHOIS + OSINT + brand check + subdomains...</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Status banner if some checks failed */}
          {(!result.whois || result.whois?.error) && (!result.osint || result.osint?.error) && (
            <div className="bg-[#ffcc00]/10 border border-[#ffcc00]/30 rounded-lg p-3 text-xs text-[#ffcc00]">
              Some lookups timed out — showing partial results. Try again for full data.
            </div>
          )}
          {/* Brand Impersonation Card — NEW */}
          {result.brand && !result.brand.error && (
            <div className={`bg-[#111119] border rounded-lg p-4 ${
              result.brand.isImpersonation ? 'border-[#ff3366]/50' : 'border-[#1a1a2e]'
            }`}>
              <h3 className={`text-sm font-bold mb-3 uppercase tracking-wide ${result.brand.isImpersonation ? 'text-[#ff3366]' : 'text-[#00ff88]'}`}>
                {result.brand.isImpersonation ? '⚠ BRAND IMPERSONATION' : 'BRAND CHECK'}
              </h3>
              {result.brand.matches?.length > 0 ? (
                <div className="space-y-2">
                  {result.brand.matches.map((m: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <div>
                        <span className="text-white font-mono">{m.brand}</span>
                        {m.homoglyphUsed && <span className="text-xs text-[#ff9900] ml-2">homoglyph</span>}
                      </div>
                      <span className={`font-bold ${m.similarity >= 85 ? 'text-[#ff3366]' : m.similarity >= 70 ? 'text-[#ffcc00]' : 'text-[#00ff88]'}`}>
                        {m.similarity}% match
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No brand matches found</p>
              )}
            </div>
          )}

          {/* WHOIS Card */}
          {result.whois && !result.whois.error && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <h3 className="text-sm font-bold text-[#00ff88] mb-3 uppercase tracking-wide">WHOIS</h3>
              <div className="grid grid-cols-2 gap-2 text-sm">
                {result.whois.registrar && <><span className="text-gray-400">Registrar</span><span className="text-white font-mono">{result.whois.registrar}</span></>}
                {result.whois.created && <><span className="text-gray-400">Created</span><span className="text-white font-mono">{new Date(result.whois.created).toLocaleDateString()}</span></>}
                {result.whois.expires && <><span className="text-gray-400">Expires</span><span className="text-white font-mono">{new Date(result.whois.expires).toLocaleDateString()}</span></>}
                {result.whois.registrant?.country && <><span className="text-gray-400">Country</span><span className="text-white">{result.whois.registrant.country}</span></>}
                {result.whois.cert_count !== undefined && <><span className="text-gray-400">SSL Certs</span><span className="text-white">{result.whois.cert_count}</span></>}
                {!result.whois.registrar && !result.whois.created && result.whois.rdap_found === false && (
                  <><span className="text-gray-400">Status</span><span className="text-[#ffcc00]">RDAP lookup failed — limited data</span></>
                )}
              </div>
              {result.whois.nameservers?.length > 0 && (
                <div className="mt-2">
                  <span className="text-gray-400 text-sm">NS: </span>
                  {result.whois.nameservers.slice(0, 3).map((ns: string) => (
                    <span key={ns} className="inline-block mr-2 text-xs font-mono text-[#00ccff] bg-[#00ccff]/10 px-2 py-0.5 rounded">{ns}</span>
                  ))}
                </div>
              )}
              {result.whois.rdap_url && (
                <a href={result.whois.rdap_url} target="_blank" className="text-xs text-[#00ff88] underline mt-2 inline-block">RDAP →</a>
              )}
            </div>
          )}
          {!result.whois && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <h3 className="text-sm font-bold text-gray-500 mb-2 uppercase tracking-wide">WHOIS</h3>
              <p className="text-xs text-gray-500">Lookup timed out — try again</p>
            </div>
          )}

          {/* OSINT Card */}
          {result.osint && !result.osint.error && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <h3 className="text-sm font-bold text-[#00ff88] mb-3 uppercase tracking-wide">OSINT</h3>
              {result.osint.title && <p className="text-white text-sm mb-2">{result.osint.title}</p>}
              {result.osint.techStack?.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-2">
                  {result.osint.techStack.map((t: string) => (
                    <span key={t} className="text-xs font-mono text-[#ff9900] bg-[#ff9900]/10 px-2 py-0.5 rounded">{t}</span>
                  ))}
                </div>
              )}
              {result.osint.emails?.length > 0 && (
                <div className="text-sm"><span className="text-gray-400">Emails: </span>{result.osint.emails.join(', ')}</div>
              )}
              {result.osint.externalDomains?.length > 0 && (
                <div className="text-sm mt-1"><span className="text-gray-400">External links: </span><span className="text-[#00ccff]">{result.osint.externalDomains.length}</span></div>
              )}
            </div>
          )}

          {/* Subdomains Card */}
          {result.enrich && !result.enrich.error && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <h3 className="text-sm font-bold text-[#00ff88] mb-3 uppercase tracking-wide">SUBDOMAINS ({result.enrich.subdomains?.length || 0})</h3>
              {result.enrich.subdomains?.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {result.enrich.subdomains.slice(0, 20).map((s: string) => (
                    <span key={s} className="text-xs font-mono text-[#cc99ff] bg-[#cc99ff]/10 px-2 py-0.5 rounded">{s}</span>
                  ))}
                </div>
              ) : <p className="text-gray-500 text-sm">No subdomains found</p>}
            </div>
          )}
        </div>
      )}
    </div>
  )
}