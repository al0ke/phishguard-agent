'use client'

import { useState } from 'react'
import AnalysisInput from '@/components/AnalysisInput'
import ScanAnimation from '@/components/ScanAnimation'
import RiskGauge from '@/components/RiskGauge'
import ThreatReport from '@/components/ThreatReport'
import IOCList from '@/components/IOCList'

type ScanPhase = 'idle' | 'extracting' | 'virustotal' | 'urlhaus' | 'brand' | 'ai' | 'complete'

interface AnalysisResult {
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
}

export default function Home() {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [scanPhase, setScanPhase] = useState<ScanPhase>('idle')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyze = async (input: string) => {
    setIsAnalyzing(true)
    setError(null)
    setResult(null)
    
    // Animate through phases
    const phases: ScanPhase[] = ['extracting', 'virustotal', 'urlhaus', 'brand', 'ai', 'complete']
    
    for (let i = 0; i < phases.length; i++) {
      setScanPhase(phases[i])
      await new Promise(resolve => setTimeout(resolve, phases[i] === 'complete' ? 500 : 800 + Math.random() * 400))
    }
    
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      })
      
      if (!response.ok) {
        throw new Error('Analysis failed')
      }
      
      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError('Failed to analyze. Please try again.')
      setScanPhase('idle')
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white">
      {/* Header */}
      <header className="border-b border-[#1a1a2e]">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#00ff88] to-[#00ccff] flex items-center justify-center">
              <span className="text-2xl">🛡️</span>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">
                <span className="text-[#00ff88]">Phish</span>
                <span className="text-white">Guard</span>
                <span className="text-[#00ccff]">Agent</span>
              </h1>
              <p className="text-xs text-gray-500">AI-Powered Threat Analysis</p>
            </div>
          </div>
          
          <nav className="flex items-center gap-6">
            <a href="#analyze" className="text-sm text-gray-400 hover:text-white transition-colors">Analyze</a>
            <a href="#report" className="text-sm text-gray-400 hover:text-white transition-colors">Report</a>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30">
              <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="text-xs text-[#00ff88]">System Online</span>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-[#00ff88]/5 to-transparent pointer-events-none" />
        <div className="max-w-6xl mx-auto px-4 py-16 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#1a1a2e] border border-[#2a2a3e] mb-6">
            <span className="text-xs text-[#00ccff]">⚡ Powered by advanced threat intelligence</span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            <span className="text-white">Detect </span>
            <span className="text-[#ff3366]">Phishing </span>
            <span className="text-white">Threats with </span>
            <span className="text-[#00ff88]">AI</span>
          </h2>
          <p className="text-gray-400 text-lg max-w-2xl mx-auto mb-8">
            Analyze URLs, emails, and domains against multiple threat intelligence sources. 
            Get instant verdicts with AI-powered recommendations.
          </p>
          <div className="flex items-center justify-center gap-8 text-sm">
            <div className="flex items-center gap-2 text-gray-400">
              <span className="text-[#00ff88]">✓</span> VirusTotal API
            </div>
            <div className="flex items-center gap-2 text-gray-400">
              <span className="text-[#00ff88]">✓</span> URLhaus Database
            </div>
            <div className="flex items-center gap-2 text-gray-400">
              <span className="text-[#00ff88]">✓</span> Brand Detection
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto px-4 pb-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Column - Input & Animation */}
          <div className="space-y-6">
            <div id="analyze">
              <AnalysisInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />
            </div>
            <ScanAnimation isScanning={isAnalyzing} scanPhase={scanPhase} />
          </div>

          {/* Right Column - Results */}
          <div className="space-y-6" id="report">
            {error && (
              <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-xl p-4">
                <p className="text-[#ff3366]">{error}</p>
              </div>
            )}
            
            {result && (
              <>
                <RiskGauge 
                  score={result.riskScore} 
                  threatLevel={result.threatLevel as any} 
                />
                <ThreatReport result={result} />
                <IOCList iocs={result.iocs} />
              </>
            )}

            {!result && !error && !isAnalyzing && (
              <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] p-12 text-center">
                <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-[#1a1a2e] flex items-center justify-center">
                  <span className="text-4xl">🔍</span>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Ready to Analyze</h3>
                <p className="text-gray-400">
                  Enter a URL or paste email content above to begin threat analysis
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Features Grid */}
        <section className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            {
              icon: '🎯',
              title: 'IOC Extraction',
              desc: 'Automatically extract IPs, domains, URLs, and hashes from suspicious content'
            },
            {
              icon: '🧠',
              title: 'AI Verdict',
              desc: 'Get intelligent threat assessments with confidence scores and recommendations'
            },
            {
              icon: '⚡',
              title: 'Real-Time Analysis',
              desc: 'Parallel queries to VirusTotal, URLhaus, and brand detection databases'
            },
          ].map((feature, i) => (
            <div key={i} className="bg-[#111119] rounded-xl border border-[#1a1a2e] p-6 hover:border-[#00ff88]/30 transition-all group">
              <div className="w-12 h-12 rounded-xl bg-[#00ff88]/10 flex items-center justify-center text-2xl mb-4 group-hover:scale-110 transition-transform">
                {feature.icon}
              </div>
              <h3 className="text-lg font-bold text-white mb-2">{feature.title}</h3>
              <p className="text-gray-400 text-sm">{feature.desc}</p>
            </div>
          ))}
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1a1a2e] py-8">
        <div className="max-w-6xl mx-auto px-4 text-center text-sm text-gray-500">
          <p>PhishGuard Agent • AI-Powered Phishing Threat Analysis</p>
          <p className="mt-2">Integrates with VirusTotal, URLhaus, and advanced brand impersonation detection</p>
        </div>
      </footer>
    </div>
  )
}