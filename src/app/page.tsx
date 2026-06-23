'use client'

import { useState, useEffect, useCallback } from 'react'
import AnalysisInput from '@/components/AnalysisInput'
import RiskGauge from '@/components/RiskGauge'
import ThreatReport from '@/components/ThreatReport'
import IOCList from '@/components/IOCList'
import DomainAnalyzer from '@/components/DomainAnalyzer'
import HashAnalyzer from '@/components/HashAnalyzer'
import WhoisLookup from '@/components/WhoisLookup'
import UrlSanitizer from '@/components/UrlSanitizer'
import ScreenshotCapture from '@/components/ScreenshotCapture'
import EmailAnalyzer from '@/components/EmailAnalyzer'
import EmlParser from '@/components/EmlParser'
import QrAnalyzer from '@/components/QrAnalyzer'
import ThreatFeeds from '@/components/ThreatFeeds'
import ReportGenerator from '@/components/ReportGenerator'
import IpAnalyzer from '@/components/IpAnalyzer'
import RedirectTracer from '@/components/RedirectTracer'
import DnsLookup from '@/components/DnsLookup'
import BulkScanner from '@/components/BulkScanner'
import Overview from '@/components/Overview'
import AuditLog from '@/components/AuditLog'
import TalosLookup from '@/components/TalosLookup'
import URLVoidScanner from '@/components/URLVoidScanner'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { InvestigateTab } from '@/lib/analyzerProps'

type Tab = 'overview' | 'url' | 'domain' | 'hash' | 'email' | 'eml' | 'dns' | 'whois' | 'ip' | 'qr' | 'redirect' | 'bulk' | 'sanitize' | 'screenshot' | 'feeds' | 'talos' | 'urlvoid' | 'audit' | 'report'

interface AnalysisResult {
  timestamp: string
  input: string
  inputType: string
  overallVerdict: string
  riskScore: number
  threatLevel: string
  urlsAnalyzed: string[]
  virusTotal?: Record<string, unknown>
  urlhaus?: Record<string, unknown>
  brandImpersonation?: Record<string, unknown>[]
  feedMatch?: { matched: boolean; sources: string[] }
  punycode?: { suspicious: boolean; reason?: string }
  domainAge?: { ageDays: number | null }
  iocs: { ips: string[]; domains: string[]; urls: string[]; hashes: string[] }
  aiVerdict: { summary: string; recommendations: string[]; confidence: number }
}

const tabs: { id: Tab; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: '◈' },
  { id: 'url', label: 'URL Scan', icon: '🔍' },
  { id: 'domain', label: 'Domain', icon: '🌐' },
  { id: 'hash', label: 'Hash', icon: '#' },
  { id: 'email', label: 'Email', icon: '✉' },
  { id: 'eml', label: 'EML Parser', icon: '📎' },
  { id: 'dns', label: 'DNS', icon: 'DNS' },
  { id: 'whois', label: 'WHOIS', icon: '📋' },
  { id: 'ip', label: 'IP Lookup', icon: '🌐' },
  { id: 'qr', label: 'QR Code', icon: '📷' },
  { id: 'redirect', label: 'Redirect', icon: '↗' },
  { id: 'bulk', label: 'Bulk Scan', icon: '⚡' },
  { id: 'sanitize', label: 'Sanitize', icon: '🛡' },
  { id: 'screenshot', label: 'Screenshot', icon: '📸' },
  { id: 'feeds', label: 'Feeds', icon: '📡' },
  { id: 'talos', label: 'Talos', icon: '🛡' },
  { id: 'urlvoid', label: 'URLVoid', icon: '🔒' },
  { id: 'audit', label: 'Audit Log', icon: '📋' },
  { id: 'report', label: 'Report', icon: '📄' },
]

const tabOrder: Tab[] = tabs.map(t => t.id)

export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [scanPhase, setScanPhase] = useState<string>('idle')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tabPrefill, setTabPrefill] = useState<{ tab: Tab; value: string } | null>(null)

  const clearPrefill = useCallback(() => setTabPrefill(null), [])

  const investigate = useCallback((tab: InvestigateTab, value: string) => {
    setTabPrefill({ tab: tab as Tab, value })
    setActiveTab(tab as Tab)
    if (tab === 'url') {
      setResult(null)
      setError(null)
    }
  }, [])

  const handleAnalyze = async (input: string) => {
    setIsAnalyzing(true)
    setError(null)
    setResult(null)
    setScanPhase('scanning')

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      })
      if (!response.ok) throw new Error('Analysis failed')
      const data = await response.json()
      setResult(data)
      setScanPhase('complete')

      const findings: string[] = [
        data.virusTotal ? `VirusTotal: ${data.virusTotal.malicious || 0} malicious` : '',
        data.urlhaus?.found ? 'URLhaus flagged' : '',
        data.brandImpersonation?.length ? 'Brand impersonation detected' : '',
        data.feedMatch?.matched ? `Threat feed: ${data.feedMatch.sources?.join(', ')}` : '',
        data.punycode?.suspicious ? 'Punycode/homograph domain' : '',
        data.domainAge?.ageDays != null && data.domainAge.ageDays < 30 ? 'Recently registered domain' : '',
      ].filter(Boolean) as string[]

      const mitreTags = await logAudit({
        tool: 'URL',
        target: input,
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        findings,
      })

      saveLastResult({
        type: 'URL',
        target: input,
        timestamp: data.timestamp || new Date().toISOString(),
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        verdict: data.overallVerdict,
        findings,
        mitreTags: mitreTags.map(t => `${t.id} — ${t.name}`),
        recommendations: data.aiVerdict?.recommendations || [],
        iocs: data.iocs,
        raw: data,
      })
    } catch {
      setError('Failed to analyze. Please try again.')
      setScanPhase('idle')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const switchTab = useCallback((tab: Tab) => {
    setActiveTab(tab)
    if (tab !== 'url') {
      setResult(null)
      setError(null)
      setScanPhase('idle')
    }
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key >= '1' && e.key <= '9') {
        e.preventDefault()
        const idx = parseInt(e.key) - 1
        if (idx < tabOrder.length) switchTab(tabOrder[idx])
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [switchTab])

  const shellProps = {
    prefill: tabPrefill?.tab === activeTab ? tabPrefill.value : null,
    onPrefillConsumed: clearPrefill,
    onInvestigate: investigate,
  }

  return (
    <div className="min-h-screen flex flex-col relative" style={{ background: 'var(--cyber-bg)', color: 'var(--text-primary)' }}>
      <div className="fixed inset-0 pointer-events-none z-0" style={{
        backgroundImage: 'url(/texas-bg.jpg)',
        backgroundSize: 'contain',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        opacity: 0.06,
      }} />
      <div className="relative z-10 flex flex-col min-h-screen">
      <header className="border-b flex-shrink-0" style={{ borderColor: 'var(--cyber-border)' }}>
        <div className="px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg flex items-center justify-center relative" style={{ background: 'linear-gradient(135deg, rgba(0,40,104,0.3), rgba(0,204,255,0.1))', border: '1px solid var(--cyber-border)' }}>
              <svg width="36" height="36" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M50 3L12 22V50C12 73 28 88 50 97C72 88 88 73 88 50V22L50 3Z" fill="rgba(0,40,104,0.4)" stroke="#00ccff" strokeWidth="3" strokeLinejoin="round"/>
                <path d="M50 18L57 39L80 39L61 53L68 74L50 61L32 74L39 53L20 39L43 39L50 18Z" fill="#ffffff" stroke="#ffffff" strokeWidth="0.5" strokeLinejoin="round"/>
              </svg>
            </div>
            <h1 className="text-xl font-bold tracking-tight leading-none">
              <span className="text-[#00ff88]">Analyst</span>
              <span style={{ color: 'var(--text-primary)' }}>Toolkit</span>
              <span style={{ color: 'var(--text-muted)' }} className="text-sm ml-2 font-normal">v2.1</span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30">
              <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="text-sm text-[#00ff88] font-medium">Online</span>
            </div>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <nav className="w-52 border-r flex-shrink-0 flex flex-col" style={{ borderColor: 'var(--cyber-border)', background: 'var(--sidebar-bg)' }}>
          <div className="flex-1 py-3 space-y-0.5 overflow-y-auto">
            {tabs.map((tab, i) => (
              <button
                key={tab.id}
                onClick={() => switchTab(tab.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-sm font-bold tracking-widest uppercase transition-all border-l-2 ${
                  activeTab === tab.id
                    ? 'border-[#00ff88] bg-[#00ff88]/5'
                    : 'border-transparent hover:bg-[#1a1a2e]'
                }`}
                style={{
                  color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
                }}
              >
                <span className="text-base w-5 text-center">{tab.icon}</span>
                {tab.label}
                {i < 9 && <span className="ml-auto text-[9px] text-gray-700">⌘{i+1}</span>}
              </button>
            ))}
          </div>
          <div className="p-3 border-t" style={{ borderColor: 'var(--cyber-border)' }}>
            <div className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
              Analyst Toolkit<br />Defense Suite
            </div>
          </div>
        </nav>

        <main className="flex-1 overflow-y-auto p-8">
          {activeTab === 'overview' ? (
            <Overview onNavigate={(tab) => switchTab(tab as Tab)} />
          ) : (
            <div className="max-w-4xl mx-auto">
              {activeTab === 'url' ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <AnalysisInput
                      onAnalyze={handleAnalyze}
                      isAnalyzing={isAnalyzing}
                      prefill={shellProps.prefill}
                      onPrefillConsumed={shellProps.onPrefillConsumed}
                    />
                    {isAnalyzing && (
                      <div className="mt-4 bg-[#111119] border border-[#1a1a2e] rounded-xl p-4 text-center">
                        <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
                        <p className="text-sm text-gray-400">Running multi-engine scan...</p>
                      </div>
                    )}
                  </div>
                  <div>
                    {error && (
                      <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-xl p-4">
                        <p className="text-[#ff3366] text-sm">{error}</p>
                      </div>
                    )}
                    {result && (
                      <>
                        <RiskGauge score={result.riskScore} threatLevel={result.threatLevel as 'critical' | 'high' | 'medium' | 'low' | 'safe'} />
                        <ThreatReport result={result as Parameters<typeof ThreatReport>[0]['result']} />
                        <IOCList iocs={result.iocs} onInvestigate={investigate} />
                      </>
                    )}
                    {!result && !error && !isAnalyzing && (
                      <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] p-8 text-center">
                        <h3 className="text-lg font-bold text-white mb-1">Ready</h3>
                        <p className="text-gray-400 text-sm">Enter a URL or email to analyze</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="max-w-2xl mx-auto space-y-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xl">{tabs.find(t => t.id === activeTab)?.icon}</span>
                    <h2 className="text-base font-bold text-[#00ff88] uppercase tracking-widest">
                      {tabs.find(t => t.id === activeTab)?.label}
                    </h2>
                  </div>

                  {activeTab === 'domain' && <DomainAnalyzer {...shellProps} />}
                  {activeTab === 'hash' && <HashAnalyzer {...shellProps} />}
                  {activeTab === 'email' && <EmailAnalyzer {...shellProps} />}
                  {activeTab === 'eml' && <EmlParser {...shellProps} />}
                  {activeTab === 'dns' && <DnsLookup {...shellProps} />}
                  {activeTab === 'whois' && <WhoisLookup {...shellProps} />}
                  {activeTab === 'ip' && <IpAnalyzer {...shellProps} />}
                  {activeTab === 'qr' && <QrAnalyzer {...shellProps} />}
                  {activeTab === 'redirect' && <RedirectTracer {...shellProps} />}
                  {activeTab === 'bulk' && <BulkScanner {...shellProps} />}
                  {activeTab === 'sanitize' && <UrlSanitizer />}
                  {activeTab === 'screenshot' && <ScreenshotCapture {...shellProps} />}
                  {activeTab === 'feeds' && <ThreatFeeds />}
                  {activeTab === 'talos' && <TalosLookup />}
                  {activeTab === 'urlvoid' && <URLVoidScanner />}
                  {activeTab === 'audit' && <AuditLog />}
                  {activeTab === 'report' && <ReportGenerator />}
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      <footer className="border-t py-2 flex-shrink-0" style={{ borderColor: 'var(--cyber-border)' }}>
        <div className="text-center text-xs" style={{ color: 'var(--text-muted)' }}>
          Analyst Toolkit v2.1
        </div>
      </footer>
      </div>
    </div>
  )
}
