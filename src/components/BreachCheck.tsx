'use client'

import { useState } from 'react'
import RiskGauge from './RiskGauge'

interface BreachResult {
  email: string
  totalBreaches: number
  totalPastes: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
  breachStats: {
    mostCommonClass: string | null
    latestBreach: string | null
    highestPwnCount: number
    verifiedBreaches: number
  }
  breaches: Array<{
    Name: string
    Title: string
    Domain: string
    BreachDate: string
    PwnCount: number
    DataClasses: string[]
    IsVerified: boolean
  }>
  recommendations: string[]
}

export default function BreachCheck() {
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<BreachResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return

    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('/api/hibp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      })

      if (!response.ok) {
        throw new Error('Breach check failed')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError('Failed to check breach database. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return '#ff3366'
      case 'high': return '#ff6600'
      case 'medium': return '#ffcc00'
      case 'low': return '#00ccff'
      default: return '#00ff88'
    }
  }

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <form onSubmit={handleCheck} className="space-y-4">
        <div className="relative">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-[#ff3366] via-[#ffcc00] to-[#ff3366] rounded-xl blur opacity-30" />
          <div className="relative bg-[#111119] rounded-xl p-6 border border-[#1a1a2e]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-[#ff3366]/10 border border-[#ff3366]/30 flex items-center justify-center">
                <span className="text-xl">🔓</span>
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Breach Detection</h3>
                <p className="text-sm text-gray-400">Check if your email has been exposed in data breaches</p>
              </div>
            </div>

            <div className="flex gap-3">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email address to check..."
                className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#ff3366]/50 focus:ring-1 focus:ring-[#ff3366]/20 font-mono"
                disabled={isLoading}
              />
              <button
                type="submit"
                disabled={!email.trim() || isLoading}
                className={`px-6 py-3 rounded-lg font-bold text-sm transition-all flex items-center gap-2 ${
                  !email.trim() || isLoading
                    ? 'bg-[#1a1a2e] text-gray-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-[#ff3366] to-[#ffcc00] text-black hover:shadow-lg hover:shadow-[#ff3366]/20'
                }`}
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Checking...
                  </>
                ) : (
                  <>
                    <span>🔍</span>
                    Check Breach
                  </>
                )}
              </button>
            </div>
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
          {/* Summary Card */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div
                  className="w-12 h-12 rounded-lg flex items-center justify-center text-2xl"
                  style={{ backgroundColor: `${getRiskColor(result.riskLevel)}20` }}
                >
                  {result.riskLevel === 'safe' ? '✅' :
                   result.riskLevel === 'low' ? '⚠️' :
                   result.riskLevel === 'medium' ? '⚠️' :
                   result.riskLevel === 'high' ? '🚨' : '🚨'}
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">{result.email}</h4>
                  <p className="text-sm text-gray-400">
                    {result.totalBreaches} breach{result.totalBreaches !== 1 ? 'es' : ''} found
                    {result.totalPastes > 0 && ` • ${result.totalPastes} paste${result.totalPastes !== 1 ? 's' : ''}`}
                  </p>
                </div>
              </div>
              <div
                className="px-4 py-2 rounded-lg font-bold text-sm"
                style={{
                  backgroundColor: `${getRiskColor(result.riskLevel)}20`,
                  color: getRiskColor(result.riskLevel)
                }}
              >
                {result.riskLevel.toUpperCase()}
              </div>
            </div>

            {/* Stats Grid */}
            <div className="p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-[#0a0a0f] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#ff3366]">{result.totalBreaches}</div>
                <div className="text-xs text-gray-400 mt-1">Total Breaches</div>
              </div>
              <div className="bg-[#0a0a0f] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#ffcc00]">{result.totalPastes}</div>
                <div className="text-xs text-gray-400 mt-1">Total Pastes</div>
              </div>
              <div className="bg-[#0a0a0f] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#00ccff]">{result.breachStats.verifiedBreaches}</div>
                <div className="text-xs text-gray-400 mt-1">Verified</div>
              </div>
              <div className="bg-[#0a0a0f] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#00ff88]">
                  {result.breachStats.highestPwnCount > 0 
                    ? `${(result.breachStats.highestPwnCount / 1000000).toFixed(1)}M`
                    : '0'}
                </div>
                <div className="text-xs text-gray-400 mt-1">Max Exposed</div>
              </div>
            </div>
          </div>

          {/* Recommendations */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#ffcc00]/10 border border-[#ffcc00]/30 flex items-center justify-center">
                <span className="text-xl">💡</span>
              </div>
              <div>
                <h4 className="text-lg font-bold text-white">Recommendations</h4>
                <p className="text-sm text-gray-400">Actions to take based on breach findings</p>
              </div>
            </div>
            <div className="p-4">
              <ul className="space-y-3">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#ffcc00]/20 text-[#ffcc00] flex items-center justify-center text-sm font-bold">
                      {i + 1}
                    </span>
                    <span className="text-gray-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Breach Details */}
          {result.breaches.length > 0 && (
            <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
              <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#ff3366]/10 border border-[#ff3366]/30 flex items-center justify-center">
                  <span className="text-xl">📋</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">Breach Details</h4>
                  <p className="text-sm text-gray-400">Specific breaches where your data was exposed</p>
                </div>
              </div>
              <div className="p-4 space-y-4">
                {result.breaches.slice(0, 10).map((breach, i) => (
                  <div key={i} className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h5 className="font-bold text-white">{breach.Title}</h5>
                        <p className="text-sm text-gray-400">{breach.Domain} • {breach.BreachDate}</p>
                      </div>
                      {breach.IsVerified && (
                        <span className="px-2 py-1 rounded bg-[#ff3366]/20 text-[#ff3366] text-xs font-bold">
                          VERIFIED
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-2 mt-3">
                      {breach.DataClasses.slice(0, 5).map((dataClass, j) => (
                        <span key={j} className="px-2 py-1 rounded bg-[#ffcc00]/10 text-[#ffcc00] text-xs">
                          {dataClass}
                        </span>
                      ))}
                    </div>
                    <p className="text-xs text-gray-500 mt-2">
                      {breach.PwnCount.toLocaleString()} accounts affected
                    </p>
                  </div>
                ))}
                {result.breaches.length > 10 && (
                  <p className="text-center text-gray-500 text-sm">
                    + {result.breaches.length - 10} more breaches
                  </p>
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
            <span className="text-4xl">🔐</span>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Check for Breaches</h3>
          <p className="text-gray-400 max-w-md mx-auto">
            Enter an email address above to check if it has been exposed in known data breaches
          </p>
        </div>
      )}
    </div>
  )
}
