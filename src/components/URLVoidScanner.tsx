'use client'

import { useState } from 'react'

interface URLVoidResult {
  target: string
  scanUrl: string
  detected: boolean
  detections: number
  totalEngines: number
  detectionList: { engine: string; status: string }[]
  safe: boolean
  domainInfo: {
    domain?: string
    ip?: string
    serverLocation?: string
    domainAge?: string
    googleSafe?: boolean
  }
  error?: string
}

export default function URLVoidScanner() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<URLVoidResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!input.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch('/api/urlvoid', {
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
      setError('Failed to scan via URLVoid.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
        <p className="text-xs text-gray-400 mb-3">
          Scan a website through 30+ blocklist engines and online reputation services.
          Detects phishing, malware distribution, and fraudulent sites.
        </p>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="Enter URL or domain (e.g. example.com or https://suspicious-site.com)"
            className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          />
          <button
            onClick={handleScan}
            disabled={loading || !input.trim()}
            className="px-6 py-2.5 bg-[#00ff88] text-black font-bold rounded-lg disabled:opacity-50 hover:bg-[#00cc70] transition-colors text-sm uppercase tracking-wider"
          >
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-sm text-gray-400">Scanning through 30+ reputation engines...</p>
        </div>
      )}

      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
          <p className="text-[#ff3366] text-sm">{error}</p>
        </div>
      )}

      {result && !result.error && (
        <div className="space-y-3">
          {/* Overall Verdict */}
          <div className={`rounded-lg p-4 border ${result.safe ? 'bg-[#00ff88]/10 border-[#00ff88]/50' : 'bg-[#ff3366]/10 border-[#ff3366]/50'}`}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Verdict</p>
                <p className={`text-lg font-bold ${result.safe ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>
                  {result.safe ? 'CLEAN' : `${result.detections} DETECTION${result.detections !== 1 ? 'S' : ''}`}
                </p>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold text-white">{result.totalEngines}</p>
                <p className="text-[10px] text-gray-500 uppercase">Engines</p>
              </div>
            </div>
          </div>

          {/* Domain Info */}
          {(result.domainInfo.ip || result.domainInfo.serverLocation || result.domainInfo.domainAge) && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Domain Information</p>
              <div className="grid grid-cols-2 gap-3">
                {result.domainInfo.domain && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Domain</p>
                    <p className="text-sm font-mono text-[#00ccff]">{result.domainInfo.domain}</p>
                  </div>
                )}
                {result.domainInfo.ip && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">IP Address</p>
                    <p className="text-sm font-mono text-white">{result.domainInfo.ip}</p>
                  </div>
                )}
                {result.domainInfo.serverLocation && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Server Location</p>
                    <p className="text-sm text-white">{result.domainInfo.serverLocation}</p>
                  </div>
                )}
                {result.domainInfo.domainAge && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Domain Age</p>
                    <p className="text-sm text-white">{result.domainInfo.domainAge}</p>
                  </div>
                )}
                {result.domainInfo.googleSafe !== undefined && (
                  <div>
                    <p className="text-[10px] text-gray-500 uppercase">Google Safe Browsing</p>
                    <p className={`text-sm ${result.domainInfo.googleSafe ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>
                      {result.domainInfo.googleSafe ? 'Safe' : 'Flagged'}
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Detection List */}
          {result.detectionList.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
                Detected by ({result.detectionList.length})
              </p>
              <div className="space-y-1.5 max-h-60 overflow-y-auto">
                {result.detectionList.map((d, i) => (
                  <div key={i} className="flex items-center justify-between border-b border-[#1a1a2e] pb-1.5 last:border-0">
                    <span className="text-xs font-mono text-white">{d.engine}</span>
                    <span className="text-[10px] text-[#ff3366] bg-[#ff3366]/10 px-2 py-0.5 rounded">FLAGGED</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan URL */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
            <p className="text-[10px] text-gray-500 uppercase mb-1">Full Report</p>
            <a
              href={result.scanUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-mono text-[#00ccff] hover:underline break-all"
            >
              {result.scanUrl}
            </a>
          </div>
        </div>
      )}
    </div>
  )
}