'use client'

import { useState, useEffect } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

function detectType(hash: string): string {
  const h = hash.trim().toLowerCase()
  if (/^[a-f0-9]{32}$/.test(h)) return 'MD5'
  if (/^[a-f0-9]{40}$/.test(h)) return 'SHA1'
  if (/^[a-f0-9]{64}$/.test(h)) return 'SHA256'
  return 'unknown'
}

interface HashDetection {
  engine: string
  result: string
  category: string
}

interface HashResult {
  hash: string
  hashType: string | null
  status: string
  message?: string
  malicious: number
  suspicious: number
  undetected: number
  harmless: number
  last_analysis_date: string | null
  ratio: string
  names?: HashDetection[]
  error?: string
}

export default function HashAnalyzer({ prefill, onPrefillConsumed }: AnalyzerShellProps) {
  const [hash, setHash] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<HashResult | null>(null)

  useEffect(() => {
    if (prefill) {
      setHash(prefill.trim())
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!hash.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hash.trim() }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Failed'); setLoading(false); return }
      setResult(data)
      const riskScore = data.malicious ? Math.min(data.malicious * 10, 100) : 0
      await logAudit({
        tool: 'HASH',
        target: hash.trim(),
        riskScore,
        threatLevel: data.status || 'unknown',
        findings: [`VirusTotal: ${data.ratio}`],
      })
      saveLastResult({
        type: 'HASH',
        target: hash.trim(),
        timestamp: new Date().toISOString(),
        riskScore,
        threatLevel: data.status || 'unknown',
        findings: [`Hash type: ${data.hashType}`, `VirusTotal detections: ${data.ratio}`],
        recommendations: [data.status === 'malicious' ? 'Block this file hash across all endpoints' : 'Review hash reputation'],
        iocs: { ips: [], domains: [], urls: [], hashes: [hash.trim()] },
        raw: data,
      })
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  const hashType = hash.trim() ? detectType(hash) : null

  return (
    <div className="space-y-4">
      <form onSubmit={analyze} className="space-y-2">
        <input
          value={hash}
          onChange={e => setHash(e.target.value)}
          placeholder="44a2e..."
          className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        {hashType && hashType !== 'unknown' && (
          <p className="text-xs text-gray-500">Detected: <span className="text-[#00ccff]">{hashType}</span></p>
        )}
        <button
          type="submit"
          disabled={!hash.trim() || loading}
          className="w-full py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50"
        >
          {loading ? 'Checking VT...' : 'Check VirusTotal'}
        </button>
      </form>

      {loading && <LoadingState message="Checking VirusTotal file reputation..." />}

      {error && <ErrorState message={error} />}

      {result && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className={`text-sm font-bold uppercase ${
              result.status === 'malicious' ? 'text-[#ff3366]' :
              result.status === 'suspicious' ? 'text-[#ffcc00]' :
              result.status === 'clean' ? 'text-[#00ff88]' : 'text-gray-400'
            }`}>
              {result.status?.toUpperCase() || 'UNKNOWN'}
            </span>
            <span className="text-sm font-mono text-white">{result.ratio}</span>
          </div>

          {result.hashType && (
            <div className="text-xs text-gray-400">Type: <span className="text-[#00ccff]">{result.hashType}</span></div>
          )}

          {result.last_analysis_date && (
            <div className="text-xs text-gray-400">Last scan: <span className="text-white font-mono">{new Date(result.last_analysis_date).toLocaleString()}</span></div>
          )}

          {result.message && (
            <p className="text-sm text-gray-400">{result.message}</p>
          )}

          {(result.names?.length ?? 0) > 0 && (
            <div>
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">Detections</p>
              <div className="space-y-1">
                {result.names?.map((n, i) => (
                  <div key={i} className="flex justify-between text-xs">
                    <span className="text-gray-300 font-mono">{n.engine}</span>
                    <span className={n.category === 'malicious' ? 'text-[#ff3366]' : 'text-[#ffcc00]'}>{n.result}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!loading && !error && !result && (
        <EmptyState icon="#" title="No hash lookup yet" description="Enter an MD5, SHA1, or SHA256 hash to check it against VirusTotal's file reputation database" />
      )}
    </div>
  )
}
