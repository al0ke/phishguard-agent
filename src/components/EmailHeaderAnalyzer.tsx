'use client'

import { useState } from 'react'

interface AuthResult {
  method: string
  result: string
  severity: string
}

interface SecurityFlag {
  type: string
  present: boolean
  value: string | null
  status: string
}

interface SuspiciousIndicator {
  type: string
  severity: string
  description: string
  rawValue?: string
}

interface RoutingHop {
  number: number
  from: string
  by: string
  with: string
  ip: string | null
  timestamp: string
}

interface FromAnalysis {
  displayName: string | null
  address: string
  domain: string
  freeProvider: boolean
  disposableProvider: boolean
}

interface EmailAnalysisResult {
  riskScore: number
  riskLevel: string
  threatIndicators: SuspiciousIndicator[]
  securityFlags: SecurityFlag[]
  authResults: AuthResult[]
  routingPath: RoutingHop[]
  fromAnalysis: FromAnalysis
  replyToAnalysis: { address: string; domain: string; matchesFrom: boolean } | null
  dateAnalysis: { sent: string | null; received: string | null; anomaly: string }
  iocs: { addresses: string[]; domains: string[]; urls: string[]; ips: string[] }
}

export default function EmailHeaderAnalyzer() {
  const [emailContent, setEmailContent] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<EmailAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!emailContent.trim()) return

    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('/api/email-headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emailContent: emailContent.trim() }),
      })

      if (!response.ok) {
        throw new Error('Email analysis failed')
      }

      const data = await response.json()
      setResult(data)
    } catch {
      setError('Failed to analyze email headers. Please check the format and try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pass': return '#00ff88'
      case 'fail': return '#ff3366'
      case 'warning': return '#ffcc00'
      default: return '#00ccff'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return '#ff3366'
      case 'medium': return '#ffcc00'
      case 'low': return '#00ccff'
      default: return '#00ff88'
    }
  }

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <form onSubmit={handleAnalyze} className="space-y-4">
        <div className="relative">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-[#00ccff] via-[#00ff88] to-[#00ccff] rounded-xl blur opacity-30" />
          <div className="relative bg-[#111119] rounded-xl p-6 border border-[#1a1a2e]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/30 flex items-center justify-center">
                <span className="text-xl">📧</span>
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Email Header Analysis</h3>
                <p className="text-sm text-gray-400">Paste full email headers including Received lines</p>
              </div>
            </div>

            <textarea
              value={emailContent}
              onChange={(e) => setEmailContent(e.target.value)}
              placeholder={`Paste email headers here...\n\nExample:\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Your Email\nDate: Mon, 15 Jun 2026 10:00:00 -0500\nAuthentication-Results: spf=fail; dkim=pass; dmarc=fail\nReceived: from mail.example.com (mail.example.com [192.0.2.1])...`}
              className="w-full h-48 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-4 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ccff]/50 focus:ring-1 focus:ring-[#00ccff]/20 resize-none font-mono text-sm"
              disabled={isLoading}
            />

            <button
              type="submit"
              disabled={!emailContent.trim() || isLoading}
              className={`mt-4 w-full py-3 rounded-lg font-bold text-sm transition-all flex items-center justify-center gap-2 ${
                !emailContent.trim() || isLoading
                  ? 'bg-[#1a1a2e] text-gray-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-[#00ccff] to-[#00ff88] text-black hover:shadow-lg hover:shadow-[#00ccff]/20'
              }`}
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Analyzing Headers...
                </>
              ) : (
                <>
                  <span>🔍</span>
                  Analyze Email Headers
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-xl p-4">
          <p className="text-[#ff3366]">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Risk Score Banner */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div
                  className="w-16 h-16 rounded-lg flex items-center justify-center text-3xl"
                  style={{ backgroundColor: `${getSeverityColor(result.riskLevel)}20` }}
                >
                  {result.riskLevel === 'safe' ? '✅' :
                   result.riskLevel === 'low' ? '⚠️' :
                   result.riskLevel === 'medium' ? '⚠️' :
                   result.riskLevel === 'high' ? '🚨' : '🚨'}
                </div>
                <div>
                  <h4 className="text-xl font-bold text-white">Risk Score: {result.riskScore}/100</h4>
                  <p className="text-sm text-gray-400">
                    {result.riskLevel === 'safe' ? 'No suspicious indicators' :
                     result.riskLevel === 'low' ? 'Minor concerns detected' :
                     result.riskLevel === 'medium' ? 'Moderate risk indicators' :
                     result.riskLevel === 'high' ? 'High risk - likely malicious' : 'Critical risk - urgent action required'}
                  </p>
                </div>
              </div>
              <div
                className="px-4 py-2 rounded-lg font-bold text-sm"
                style={{
                  backgroundColor: `${getSeverityColor(result.riskLevel)}20`,
                  color: getSeverityColor(result.riskLevel)
                }}
              >
                {result.riskLevel.toUpperCase()}
              </div>
            </div>
          </div>

          {/* Authentication Results */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center">
                <span className="text-xl">🔐</span>
              </div>
              <div>
                <h4 className="text-lg font-bold text-white">Authentication Status</h4>
                <p className="text-sm text-gray-400">SPF, DKIM, DMARC verification results</p>
              </div>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {result.authResults.length > 0 ? result.authResults.map((auth, i) => (
                  <div key={i} className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-white uppercase">{auth.method}</span>
                      <span
                        className="px-2 py-1 rounded text-xs font-bold"
                        style={{
                          backgroundColor: `${getStatusColor(auth.severity)}20`,
                          color: getStatusColor(auth.severity)
                        }}
                      >
                        {auth.result.toUpperCase()}
                      </span>
                    </div>
                  </div>
                )) : (
                  <div className="col-span-3 text-center py-4 text-gray-500">
                    No authentication results found
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Sender Analysis */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/30 flex items-center justify-center">
                <span className="text-xl">👤</span>
              </div>
              <div>
                <h4 className="text-lg font-bold text-white">Sender Analysis</h4>
                <p className="text-sm text-gray-400">From header and reply-to analysis</p>
              </div>
            </div>
            <div className="p-4">
              <div className="space-y-4">
                <div className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                  <div className="text-xs text-gray-400 mb-1">From Address</div>
                  <div className="font-mono text-white">{result.fromAnalysis.address}</div>
                  {result.fromAnalysis.displayName && (
                    <div className="text-sm text-gray-400 mt-1">Display Name: {result.fromAnalysis.displayName}</div>
                  )}
                  <div className="flex gap-2 mt-2">
                    {result.fromAnalysis.freeProvider && (
                      <span className="px-2 py-1 rounded bg-[#ffcc00]/10 text-[#ffcc00] text-xs">Free Provider</span>
                    )}
                    {result.fromAnalysis.disposableProvider && (
                      <span className="px-2 py-1 rounded bg-[#ff3366]/10 text-[#ff3366] text-xs">Disposable Email</span>
                    )}
                  </div>
                </div>

                {result.replyToAnalysis && !result.replyToAnalysis.matchesFrom && (
                  <div className="bg-[#ff3366]/5 rounded-lg p-4 border border-[#ff3366]/30">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-[#ff3366]">⚠️</span>
                      <span className="text-sm font-bold text-[#ff3366]">Reply-To Mismatch</span>
                    </div>
                    <div className="font-mono text-sm text-gray-300">
                      Reply-To: {result.replyToAnalysis.address}
                    </div>
                    <div className="text-xs text-gray-500 mt-1">
                      Domain differs from From address
                    </div>
                  </div>
                )}

                {result.dateAnalysis.anomaly !== 'none' && (
                  <div className="bg-[#ffcc00]/5 rounded-lg p-4 border border-[#ffcc00]/30">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-[#ffcc00]">⚠️</span>
                      <span className="text-sm font-bold text-[#ffcc00]">Date Anomaly</span>
                    </div>
                    <div className="text-sm text-gray-300">
                      {result.dateAnalysis.anomaly === 'future_date' && 'Email date is in the future'}
                      {result.dateAnalysis.anomaly === 'distant_past' && 'Email date is suspiciously old'}
                      {result.dateAnalysis.anomaly === 'missing' && 'Date header is missing or malformed'}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Suspicious Indicators */}
          {result.threatIndicators.length > 0 && (
            <div className="bg-[#111119] rounded-xl border border-[#ff3366]/30 overflow-hidden">
              <div className="bg-[#ff3366]/10 px-4 py-3 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#ff3366]/20 flex items-center justify-center">
                  <span className="text-xl">🚩</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-[#ff3366]">Suspicious Indicators</h4>
                  <p className="text-sm text-gray-400">{result.threatIndicators.length} indicator(s) found</p>
                </div>
              </div>
              <div className="p-4 space-y-3">
                {result.threatIndicators.map((indicator, i) => (
                  <div key={i} className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="px-2 py-0.5 rounded text-xs font-bold uppercase"
                            style={{
                              backgroundColor: `${getSeverityColor(indicator.severity)}20`,
                              color: getSeverityColor(indicator.severity)
                            }}
                          >
                            {indicator.severity}
                          </span>
                          <span className="text-xs text-gray-500 uppercase">{indicator.type.replace(/_/g, ' ')}</span>
                        </div>
                        <p className="text-gray-300 text-sm">{indicator.description}</p>
                        {indicator.rawValue && (
                          <code className="text-xs text-gray-500 mt-1 block">{indicator.rawValue}</code>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Routing Path */}
          {result.routingPath.length > 0 && (
            <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
              <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center">
                  <span className="text-xl">🛤️</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">Email Routing Path</h4>
                  <p className="text-sm text-gray-400">{result.routingPath.length} hop(s) in the path</p>
                </div>
              </div>
              <div className="p-4">
                <div className="space-y-3">
                  {[...result.routingPath].reverse().map((hop, i) => (
                    <div key={i} className="flex items-center gap-4">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-[#00ccff]/20 text-[#00ccff] flex items-center justify-center text-sm font-bold">
                        {hop.number}
                      </div>
                      <div className="flex-1 bg-[#0a0a0f] rounded-lg p-3 border border-[#1a1a2e]">
                        <div className="flex items-center gap-2 text-xs text-gray-400 mb-1">
                          <span>From: {hop.from}</span>
                          <span>→</span>
                          <span>By: {hop.by}</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-gray-400">
                          <span>via {hop.with}</span>
                          {hop.ip && <span className="font-mono text-[#00ccff]">[{hop.ip}]</span>}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">{hop.timestamp}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Extracted IOCs */}
          {result.iocs.addresses.length > 0 && (
            <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
              <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#ffcc00]/10 border border-[#ffcc00]/30 flex items-center justify-center">
                  <span className="text-xl">🎯</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">Extracted IOCs</h4>
                  <p className="text-sm text-gray-400">Email addresses, URLs, IPs found</p>
                </div>
              </div>
              <div className="p-4 space-y-4">
                {result.iocs.addresses.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-400 mb-2">Email Addresses</div>
                    <div className="flex flex-wrap gap-2">
                      {result.iocs.addresses.map((addr, i) => (
                        <span key={i} className="px-3 py-1 rounded bg-[#00ccff]/10 text-[#00ccff] text-xs font-mono">
                          {addr}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.iocs.ips.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-400 mb-2">IP Addresses</div>
                    <div className="flex flex-wrap gap-2">
                      {result.iocs.ips.map((ip, i) => (
                        <span key={i} className="px-3 py-1 rounded bg-[#ff3366]/10 text-[#ff3366] text-xs font-mono">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.iocs.urls.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-400 mb-2">URLs</div>
                    <div className="flex flex-wrap gap-2">
                      {result.iocs.urls.slice(0, 10).map((url, i) => (
                        <span key={i} className="px-3 py-1 rounded bg-[#ffcc00]/10 text-[#ffcc00] text-xs font-mono break-all">
                          {url.slice(0, 60)}{url.length > 60 ? '...' : ''}
                        </span>
                      ))}
                      {result.iocs.urls.length > 10 && (
                        <span className="text-xs text-gray-500">+{result.iocs.urls.length - 10} more</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!result && !error && !isLoading && (
        <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] p-12 text-center">
          <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-[#1a1a2e] flex items-center justify-center">
            <span className="text-4xl">📧</span>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Email Header Analyzer</h3>
          <p className="text-gray-400 max-w-md mx-auto">
            Paste full email headers above to analyze authentication results, routing path, and detect spoofing attempts
          </p>
        </div>
      )}
    </div>
  )
}
