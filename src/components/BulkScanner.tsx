'use client'

import { useState, useEffect } from 'react'
import { logAudit } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

export default function BulkScanner({ prefill, onPrefillConsumed, onInvestigate }: AnalyzerShellProps) {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [progress, setProgress] = useState('')

  useEffect(() => {
    if (prefill) {
      setInput(prefill.trim())
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const scan = async (e: React.FormEvent) => {
    e.preventDefault()
    const lines = input.split('\n').map(l => l.trim()).filter(Boolean)
    if (!lines.length) return

    setLoading(true)
    setResults([])
    setProgress(`Scanning ${lines.length} indicators...`)

    const scanned: any[] = []

    for (let i = 0; i < lines.length; i++) {
      const target = lines[i]
      setProgress(`Scanning ${i + 1}/${lines.length}: ${target}`)

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: target }),
        })
        if (res.ok) {
          const data = await res.json()
          scanned.push({
            target,
            type: data.inputType || 'URL',
            riskScore: data.riskScore || 0,
            threatLevel: data.threatLevel || 'unknown',
            verdict: data.overallVerdict || '',
            iocCount: (data.iocs?.ips?.length || 0) + (data.iocs?.domains?.length || 0) + (data.iocs?.urls?.length || 0),
          })
        } else {
          scanned.push({ target, type: 'error', riskScore: 0, threatLevel: 'error', verdict: 'Scan failed', iocCount: 0 })
        }
      } catch {
        scanned.push({ target, type: 'error', riskScore: 0, threatLevel: 'error', verdict: 'Network error', iocCount: 0 })
      }
      setResults([...scanned])
    }

    setProgress('')
    setLoading(false)

    const maxScore = Math.max(...scanned.map(r => r.riskScore || 0), 0)
    const worst = scanned.find(r => r.riskScore === maxScore)
    const threatCount = scanned.filter(r => r.threatLevel === 'critical' || r.threatLevel === 'high').length
    const mediumCount = scanned.filter(r => r.threatLevel === 'medium').length
    await logAudit({
      tool: 'BULK',
      target: `${lines.length} indicators`,
      riskScore: maxScore,
      threatLevel: worst?.threatLevel || 'unknown',
      findings: [`${threatCount} high/critical`, `${mediumCount} medium`],
    })
  }

  const stats = {
    total: results.length,
    malicious: results.filter(r => r.threatLevel === 'critical' || r.threatLevel === 'high').length,
    medium: results.filter(r => r.threatLevel === 'medium').length,
    clean: results.filter(r => r.threatLevel === 'low' || r.threatLevel === 'clean').length,
  }

  return (
    <div className="space-y-4">
      <form onSubmit={scan} className="space-y-3">
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Paste URLs, IPs, domains — one per line&#10;https://suspicious.com&#10;192.168.1.1&#10;evil-domain.com"
          rows={6}
          className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm resize-y"
          disabled={loading}
        />
        <button type="submit" disabled={!input.trim() || loading} className="w-full py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? progress : '⚡ Bulk Scan'}
        </button>
      </form>

      {results.length > 0 && (
        <div className="space-y-3">
          {/* Stats */}
          <div className="grid grid-cols-4 gap-2">
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-2 text-center">
              <p className="text-xs text-gray-400">Total</p>
              <p className="text-lg font-bold text-white">{stats.total}</p>
            </div>
            <div className="bg-[#ff3366]/10 border border-[#ff3366]/30 rounded-lg p-2 text-center">
              <p className="text-xs text-gray-400">Threats</p>
              <p className="text-lg font-bold text-[#ff3366]">{stats.malicious}</p>
            </div>
            <div className="bg-[#ffcc00]/10 border border-[#ffcc00]/30 rounded-lg p-2 text-center">
              <p className="text-xs text-gray-400">Medium</p>
              <p className="text-lg font-bold text-[#ffcc00]">{stats.medium}</p>
            </div>
            <div className="bg-[#00ff88]/10 border border-[#00ff88]/30 rounded-lg p-2 text-center">
              <p className="text-xs text-gray-400">Clean</p>
              <p className="text-lg font-bold text-[#00ff88]">{stats.clean}</p>
            </div>
          </div>

          {/* Results table */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1a1a2e] text-gray-400 uppercase">
                  <th className="text-left px-3 py-2">Target</th>
                  <th className="text-center px-2 py-2">Score</th>
                  <th className="text-center px-2 py-2">Level</th>
                  <th className="text-right px-3 py-2">IOCs</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i} className="border-b border-[#1a1a2e] last:border-0">
                    <td className="px-3 py-2 font-mono text-white break-all max-w-[200px]">
                      {onInvestigate ? (
                        <button type="button" onClick={() => onInvestigate(r.target.startsWith('http') ? 'url' : r.target.match(/^\d/) ? 'ip' : 'domain', r.target)} className="text-left hover:text-[#00ccff] hover:underline">
                          {r.target}
                        </button>
                      ) : r.target}
                    </td>
                    <td className="px-2 py-2 text-center">
                      <span className={`font-bold ${
                        r.riskScore >= 70 ? 'text-[#ff3366]' :
                        r.riskScore >= 40 ? 'text-[#ffcc00]' : 'text-[#00ff88]'
                      }`}>{r.riskScore}</span>
                    </td>
                    <td className="px-2 py-2 text-center">
                      <span className={`text-[10px] font-bold uppercase ${
                        r.threatLevel === 'critical' || r.threatLevel === 'high' ? 'text-[#ff3366]' :
                        r.threatLevel === 'medium' ? 'text-[#ffcc00]' :
                        r.threatLevel === 'error' ? 'text-gray-500' : 'text-[#00ff88]'
                      }`}>{r.threatLevel}</span>
                    </td>
                    <td className="px-3 py-2 text-right text-gray-400">{r.iocCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}