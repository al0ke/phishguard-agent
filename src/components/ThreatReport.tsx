'use client'

import { memo } from 'react'

interface ThreatReportProps {
  result: {
    timestamp: string
    input: string
    inputType: string
    overallVerdict: string
    riskScore: number
    threatLevel: string
    urlsAnalyzed: string[]
    virusTotal?: {
      status: string
      malicious: number
      suspicious: number
      ratio: string
      lastAnalysisDate: string
    }
    urlhaus?: {
      status: string
      threatType: string | null
      firstSeen: string
      country?: string
      hausScore?: number
    }
    brandImpersonation?: {
      brand: string
      originalDomain: string
      suspectedDomain: string
      riskLevel: string
      techniques: string[]
    }[]
    iocs: {
      ips: string[]
      domains: string[]
      urls: string[]
      hashes: string[]
    }
    aiVerdict: {
      summary: string
      recommendations: string[]
      confidence: number
    }
    feedMatch?: {
      matched: boolean
      sources: string[]
    }
    punycode?: {
      suspicious: boolean
      reason?: string
    }
    domainAge?: {
      ageDays: number | null
    }
  }
}

function ThreatReport({ result }: ThreatReportProps) {
  const colorMap: Record<string, {bg: string, border: string, text: string}> = {
    malicious: { bg: 'bg-[#ff3366]/10', border: 'border-[#ff3366]/50', text: 'text-[#ff3366]' },
    suspicious: { bg: 'bg-[#ffcc00]/10', border: 'border-[#ffcc00]/50', text: 'text-[#ffcc00]' },
    safe: { bg: 'bg-[#00ff88]/10', border: 'border-[#00ff88]/50', text: 'text-[#00ff88]' },
  }
  const colors = colorMap[result.overallVerdict] || { bg: 'bg-[#00ccff]/10', border: 'border-[#00ccff]/50', text: 'text-[#00ccff]' }

  const verdictBg = result.overallVerdict === 'malicious' ? 'bg-[#ff3366]/20' : result.overallVerdict === 'suspicious' ? 'bg-[#ffcc00]/20' : 'bg-[#00ff88]/20'
  const verdictIcon = result.overallVerdict === 'malicious' ? '🚨' : result.overallVerdict === 'suspicious' ? '⚠️' : '✅'
  const verdictLabel = result.overallVerdict === 'malicious' ? 'THREAT CONFIRMED' : result.overallVerdict === 'suspicious' ? 'SUSPICIOUS ACTIVITY' : result.overallVerdict === 'safe' ? 'CLEAN' : 'UNCLEAR RISK'

  const vtStatusBadge = result.virusTotal ? (result.virusTotal.status === 'malicious' ? 'bg-[#ff3366]/20 text-[#ff3366]' : result.virusTotal.status === 'suspicious' ? 'bg-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#00ff88]/20 text-[#00ff88]') : ''
  const vtStatusText = result.virusTotal ? result.virusTotal.status.toUpperCase() : ''

  const urlhausStatusBadge = result.urlhaus ? (result.urlhaus.status === 'malicious' ? 'bg-[#ff3366]/20 text-[#ff3366]' : result.urlhaus.status === 'suspicious' ? 'bg-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#00ff88]/20 text-[#00ff88]') : ''
  const urlhausStatusText = result.urlhaus ? result.urlhaus.status.toUpperCase() : ''

  const timestamp = new Date(result.timestamp).toLocaleString()
  const confidencePct = Math.round(result.aiVerdict.confidence * 100)
  const firstSeenDate = result.urlhaus ? result.urlhaus.firstSeen.split(' ')[0] : ''

  return (
    <div className="space-y-6">
      <div className={`${colors.bg} rounded-xl border ${colors.border} p-6`}>
        <div className="flex items-center gap-4">
          <div className={`w-16 h-16 rounded-full flex items-center justify-center text-3xl ${verdictBg}`}>
            {verdictIcon}
          </div>
          <div className="flex-1">
            <h2 className={`text-2xl font-bold ${colors.text}`}>{verdictLabel}</h2>
            <p className="text-gray-300 mt-1">{result.aiVerdict.summary}</p>
            <div className="flex items-center gap-4 mt-3">
              <span className="text-sm text-gray-400">Confidence: <span className={colors.text}>{confidencePct}%</span></span>
              <span className="text-sm text-gray-400">Input type: <span className="text-white">{result.inputType}</span></span>
            </div>
          </div>
        </div>
      </div>

      {(result.feedMatch?.matched ||
        result.punycode?.suspicious ||
        result.domainAge?.ageDays != null) && (
        <div className="bg-[#111119] rounded-xl border border-[#ffcc00]/30 p-4 space-y-2">
          <h3 className="text-sm font-bold text-[#ffcc00] uppercase tracking-wide">Phishing Signals</h3>
          {result.feedMatch?.matched && (
            <p className="text-sm text-gray-300">Threat feed match: {result.feedMatch.sources.join(', ')}</p>
          )}
          {result.punycode?.suspicious && (
            <p className="text-sm text-gray-300">{result.punycode.reason || 'Suspicious IDN domain'}</p>
          )}
          {result.domainAge?.ageDays != null && (
            <p className="text-sm text-gray-300">
              Domain age: {result.domainAge.ageDays} days
              {result.domainAge.ageDays < 30 ? ' — recently registered' : ''}
            </p>
          )}
        </div>
      )}

      <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
        <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/30 flex items-center justify-center">
            <span className="text-xl">💡</span>
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Threat Recommendations</h3>
            <p className="text-sm text-gray-400">Suggested actions based on analysis</p>
          </div>
        </div>
        <div className="p-4">
          <ul className="space-y-3">
            {result.aiVerdict.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#00ccff]/20 text-[#00ccff] flex items-center justify-center text-sm font-bold">
                  {i + 1}
                </span>
                <span className="text-gray-300">{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
          <div className="bg-[#1a1a2e] px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-[#00ff88]/10 flex items-center justify-center text-sm">🔬</div>
              <span className="font-bold text-white">VirusTotal</span>
            </div>
            {result.virusTotal && (
              <span className={`px-2 py-1 rounded text-xs font-bold ${vtStatusBadge}`}>{vtStatusText}</span>
            )}
          </div>
          <div className="p-4">
            {result.virusTotal ? (
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Malicious vendors</span>
                  <span className="text-xl font-bold text-[#ff3366]">{result.virusTotal.malicious}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Suspicious vendors</span>
                  <span className="text-xl font-bold text-[#ffcc00]">{result.virusTotal.suspicious}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Detection ratio</span>
                  <span className="text-white font-mono">{result.virusTotal.ratio}</span>
                </div>
                {result.virusTotal.lastAnalysisDate && (
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Last analyzed</span>
                    <span className="text-gray-300 text-sm">
                      {new Date(parseInt(result.virusTotal.lastAnalysisDate) * 1000).toLocaleDateString()}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-4 text-gray-500">No VirusTotal data available</div>
            )}
          </div>
        </div>

        <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
          <div className="bg-[#1a1a2e] px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-[#ffcc00]/10 flex items-center justify-center text-sm">🛡️</div>
              <span className="font-bold text-white">URLhaus</span>
            </div>
            {result.urlhaus && (
              <span className={`px-2 py-1 rounded text-xs font-bold ${urlhausStatusBadge}`}>{urlhausStatusText}</span>
            )}
          </div>
          <div className="p-4">
            {result.urlhaus ? (
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Threat type</span>
                  <span className="text-white">{result.urlhaus.threatType || 'N/A'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">First seen</span>
                  <span className="text-gray-300 text-sm">{firstSeenDate}</span>
                </div>
                {result.urlhaus.country && (
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Country</span>
                    <span className="text-white">{result.urlhaus.country}</span>
                  </div>
                )}
                {result.urlhaus.hausScore !== undefined && (
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">URLhaus score</span>
                    <span className="text-[#ffcc00] font-bold">{result.urlhaus.hausScore}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-4 text-gray-500">No URLhaus data available</div>
            )}
          </div>
        </div>
      </div>

      {result.brandImpersonation && result.brandImpersonation.length > 0 && (
        <div className="bg-[#111119] rounded-xl border border-[#ff3366]/30 overflow-hidden">
          <div className="bg-[#ff3366]/10 px-4 py-3 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#ff3366]/20 flex items-center justify-center">
              <span className="text-xl">🎭</span>
            </div>
            <div>
              <h3 className="text-lg font-bold text-[#ff3366]">Brand Impersonation Detected</h3>
              <p className="text-sm text-gray-400">Potential spoofing attempts identified</p>
            </div>
          </div>
          <div className="p-4 space-y-4">
            {result.brandImpersonation.map((brand, i) => {
              const riskBadge = brand.riskLevel === 'high' ? 'bg-[#ff3366]/20 text-[#ff3366]' : brand.riskLevel === 'medium' ? 'bg-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#00ccff]/20 text-[#00ccff]'
              const riskText = brand.riskLevel.toUpperCase() + ' RISK'
              return (
                <div key={i} className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-lg font-bold text-white">{brand.brand}</span>
                    <span className={`px-2 py-1 rounded text-xs font-bold ${riskBadge}`}>{riskText}</span>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Legitimate domain</span>
                      <code className="text-[#00ff88]">{brand.originalDomain}</code>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Suspected domain</span>
                      <code className="text-[#ff3366]">{brand.suspectedDomain}</code>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {brand.techniques.map((tech, j) => (
                      <span key={j} className="px-2 py-1 rounded bg-[#ffcc00]/10 text-[#ffcc00] text-xs">{tech}</span>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="text-center text-sm text-gray-500">
        Analysis completed: {timestamp}
        <span className="mx-2">•</span>
        {result.urlsAnalyzed.length} URL(s) analyzed
      </div>
    </div>
  )
}

export default memo(ThreatReport)
