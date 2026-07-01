'use client'

import { useState, useEffect } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

interface RedirectHop {
  url: string
  status: number
  redirect: string | null
}

interface RedirectResult {
  originalUrl: string
  finalUrl: string
  hops: RedirectHop[]
  hopCount: number
  securityHeaders: Record<string, string | null>
  hasSecurityIssues: boolean
  riskScore: number
  findings: string[]
  threatLevel: string
  error?: string
}

export default function RedirectTracer({ prefill, onPrefillConsumed, onInvestigate }: AnalyzerShellProps) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RedirectResult | null>(null)

  useEffect(() => {
    if (prefill) {
      setUrl(prefill.trim())
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const trace = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/redirect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Trace failed'); setLoading(false); return }
      setResult(data)
      await logAudit({
        tool: 'REDIRECT',
        target: url.trim(),
        riskScore: data.riskScore as number,
        threatLevel: data.threatLevel as string,
        findings: (data.findings as string[]) || [],
      })
      saveLastResult({
        type: 'REDIRECT TRACE',
        target: url.trim(),
        timestamp: new Date().toISOString(),
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        findings: data.findings,
        recommendations: [(data.hopCount as number) > 3 ? 'Excessive redirects — investigate final destination' : 'Review redirect chain'],
        iocs: {
          ips: [],
          domains: [data.finalUrl ? (() => { try { return new URL(data.finalUrl as string).hostname } catch { return '' } })() : ''].filter(Boolean),
          urls: [data.originalUrl, data.finalUrl].filter(Boolean) as string[],
          hashes: [],
        },
        raw: data,
      })
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={trace} className="flex gap-2">
        <input
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="http://suspicious-url.com"
          className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        <button type="submit" disabled={!url.trim() || loading} className="px-6 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? 'Tracing...' : 'Trace'}
        </button>
      </form>

      {loading && <LoadingState message="Following redirect chain and inspecting security headers..." />}

      {error && <ErrorState message={error} />}

      {result && (
        <div className="space-y-3">
          {/* Summary */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-400">FINAL DESTINATION</p>
                <p className="text-sm font-mono text-white break-all">{result.finalUrl}</p>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-400">HOPS</p>
                <p className="text-2xl font-bold text-[#00ff88]">{result.hopCount}</p>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-400">Risk:</span>
              <span className={`text-xs font-bold ${result.riskScore >= 70 ? 'text-[#ff3366]' : result.riskScore >= 40 ? 'text-[#ffcc00]' : 'text-[#00ff88]'}`}>
                {result.riskScore}/100 — {result.threatLevel?.toUpperCase()}
              </span>
              {onInvestigate && result.finalUrl && (
                <button type="button" onClick={() => onInvestigate('url', result.finalUrl)} className="text-[10px] text-[#00ccff] underline">
                  Scan final URL →
                </button>
              )}
            </div>
          </div>

          {/* Redirect Chain */}
          {result.hops?.length > 1 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Redirect Chain</p>
              <div className="space-y-1">
                {result.hops.map((hop, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="text-gray-500 font-mono mt-0.5">{i + 1}.</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-mono break-all">{hop.url}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                          hop.status >= 300 && hop.status < 400 ? 'text-[#ffcc00] bg-[#ffcc00]/10' :
                          hop.status >= 200 && hop.status < 300 ? 'text-[#00ff88] bg-[#00ff88]/10' :
                          'text-[#ff3366] bg-[#ff3366]/10'
                        }`}>{hop.status || 'TIMEOUT'}</span>
                        {hop.redirect && <span className="text-gray-500 text-[10px]">→ {hop.redirect.slice(0, 60)}...</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Headers */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Security Headers</p>
            <div className="space-y-1">
              {Object.entries(result.securityHeaders || {}).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between text-xs">
                  <span className="text-gray-400 font-mono">{key}</span>
                  <span className={value ? 'text-[#00ff88]' : 'text-[#ff3366]'}>
                    {value ? '✓' : '✗'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Findings */}
          {result.findings?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Findings</p>
              {result.findings.map((f: string, i: number) => (
                <div key={i} className="text-xs text-gray-300 flex items-start gap-1 mb-0.5">
                  <span className="text-gray-500">•</span> {f}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && !error && !result && (
        <EmptyState icon="↗" title="No redirect trace yet" description="Enter a URL to follow its full redirect chain and inspect security headers on the final destination" />
      )}
    </div>
  )
}