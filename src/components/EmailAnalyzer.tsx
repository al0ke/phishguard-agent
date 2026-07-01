'use client'

import { useState, useRef } from 'react'
import { logAudit, saveLastResult, saveTriageSession } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

function generateExplanation(r: Record<string, unknown>): string {
  if (!r) return ''
  const parts: string[] = []
  const riskScore = r.riskScore as number
  const isHigh = riskScore >= 70
  const isMed = riskScore >= 40 && riskScore < 70

  if (isHigh) parts.push(`This email poses a HIGH risk to the organization (score: ${riskScore}/100).`)
  else if (isMed) parts.push(`This email shows MODERATE risk indicators (score: ${riskScore}/100).`)
  else parts.push(`This email appears LOW risk (score: ${riskScore}/100), but remain vigilant.`)

  const spf = r.spf as { found?: boolean } | undefined
  const dkim = r.dkim as { found?: boolean } | undefined
  const dmarc = r.dmarc as { found?: boolean; policy?: string } | undefined
  const authIssues: string[] = []
  if (!spf?.found) authIssues.push('SPF record is missing')
  if (!dkim?.found) authIssues.push('DKIM signature not found')
  if (!dmarc?.found) authIssues.push('DMARC policy is missing')
  else if (dmarc?.policy === 'none') authIssues.push('DMARC is set to "none"')

  if (authIssues.length > 0) parts.push(`Email authentication failures: ${authIssues.join('; ')}.`)
  else if (spf?.found && dkim?.found && dmarc?.found) {
    parts.push('Email authentication passes all checks (SPF, DKIM, DMARC present).')
  }

  const domainInfo = r.domainInfo as { ageDays?: number | null; created?: string } | undefined
  const domain = r.domain as string | undefined
  if (domainInfo?.ageDays != null) {
    if (domainInfo.ageDays < 7) parts.push(`Sender domain "${domain}" registered ${domainInfo.ageDays} days ago — strong phishing indicator.`)
    else if (domainInfo.ageDays < 30) parts.push(`Sender domain registered ${domainInfo.ageDays} days ago — treat with suspicion.`)
  }

  const keywords = r.suspiciousKeywords as string[] | undefined
  if (keywords && keywords.length > 5) {
    parts.push(`${keywords.length} suspicious keywords detected.`)
  }

  const urls = r.urls as string[] | undefined
  if (urls && urls.length > 0) parts.push(`${urls.length} URL(s) found in the email body.`)

  return parts.join(' ')
}

type EmailMode = 'manual' | 'raw' | 'file' | 'headers'

export default function EmailAnalyzer({ onInvestigate }: AnalyzerShellProps) {
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<EmailMode>('manual')
  const [senderEmail, setSenderEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [triageLoading, setTriageLoading] = useState(false)
  const [triageProgress, setTriageProgress] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [headerResult, setHeaderResult] = useState<Record<string, unknown> | null>(null)
  const [triageResult, setTriageResult] = useState<Record<string, unknown> | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const rawContent = mode === 'raw' || mode === 'file' || mode === 'headers' ? input : ''

  const persistEmailResult = async (data: Record<string, unknown>, target: string, tool = 'EMAIL') => {
    const findings = (data.factors as string[]) || []
    if ((data.suspiciousKeywords as string[] | undefined)?.length) findings.push('Suspicious keywords detected')
    if (!((data.spf as { found?: boolean })?.found)) findings.push('SPF missing')

    await logAudit({
      tool,
      target,
      riskScore: data.riskScore as number,
      threatLevel: data.threatLevel as string,
      findings,
    })

    saveLastResult({
      type: tool,
      target,
      timestamp: new Date().toISOString(),
      riskScore: data.riskScore,
      threatLevel: data.threatLevel,
      findings: data.factors || [],
      recommendations: [
        (data.riskScore as number) >= 70 ? 'Block sender domain immediately' : null,
        !((data.spf as { found?: boolean })?.found) ? 'SPF record missing on sender domain' : null,
        (data.domainInfo as { ageDays?: number })?.ageDays != null && (data.domainInfo as { ageDays: number }).ageDays < 30 ? 'Newly registered domain — high risk' : null,
      ].filter(Boolean),
      iocs: { ips: [], domains: data.domain ? [data.domain as string] : [], urls: (data.urls as string[]) || [], hashes: [] },
      raw: data,
    })
  }

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)
    setHeaderResult(null)
    setTriageResult(null)

    try {
      if (mode === 'headers') {
        const res = await fetch('/api/email-headers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ emailContent: input.trim() }),
        })
        const data = await res.json()
        if (!res.ok) { setError(data.error || 'Header analysis failed'); setLoading(false); return }
        setHeaderResult(data)
        const fromAddr = (data.fromAnalysis as { address?: string })?.address || 'email-headers'
        await logAudit({
          tool: 'EMAIL_HEADERS',
          target: fromAddr,
          riskScore: data.riskScore,
          threatLevel: data.riskLevel,
          findings: (data.threatIndicators as { description?: string }[])?.map(i => i.description || '') || [],
        })
        saveLastResult({
          type: 'EMAIL_HEADERS',
          target: fromAddr,
          timestamp: new Date().toISOString(),
          riskScore: data.riskScore,
          threatLevel: data.riskLevel,
          findings: (data.threatIndicators as { description?: string }[])?.map(i => i.description || '') || [],
          recommendations: ['Review Reply-To and authentication results', 'Escalate if display name impersonation detected'],
          iocs: data.iocs || { ips: [], domains: [], urls: [], hashes: [] },
          raw: data,
        })
        setLoading(false)
        return
      }

      const body: Record<string, string> = {}
      if (mode === 'manual') {
        body.senderEmail = senderEmail
        body.fromDomain = senderEmail.split('@')[1] || ''
      } else {
        body.rawEmail = input
      }

      const res = await fetch('/api/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Analysis failed'); setLoading(false); return }
      setResult(data)
      await persistEmailResult(data, (data.sender as string) || (data.domain as string) || senderEmail)
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  const runFullTriage = async () => {
    if (!rawContent.trim()) return
    setTriageLoading(true)
    setError(null)
    setTriageResult(null)
    setTriageProgress('Running email + header analysis...')

    try {
      const [emailRes, headersRes] = await Promise.all([
        fetch('/api/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rawEmail: rawContent.trim() }),
        }),
        fetch('/api/email-headers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ emailContent: rawContent.trim() }),
        }),
      ])

      const emailData = emailRes.ok ? await emailRes.json() : null
      const headersData = headersRes.ok ? await headersRes.json() : null

      if (!emailData && !headersData) {
        setError('Full triage failed — could not parse email')
        setTriageLoading(false)
        return
      }

      setResult(emailData)
      setHeaderResult(headersData)

      const urlSet = new Set<string>([
        ...((emailData?.urls as string[]) || []),
        ...((headersData?.iocs?.urls as string[]) || []),
      ])
      const urls = [...urlSet].slice(0, 8)
      const urlScans: Record<string, unknown>[] = []

      for (let i = 0; i < urls.length; i++) {
        setTriageProgress(`Scanning URL ${i + 1}/${urls.length}...`)
        try {
          const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input: urls[i] }),
          })
          if (res.ok) urlScans.push(await res.json())
        } catch { /* continue */ }
      }

      const scores = [
        emailData?.riskScore as number | undefined,
        headersData?.riskScore as number | undefined,
        ...urlScans.map(u => u.riskScore as number),
      ].filter((s): s is number => typeof s === 'number')

      const maxScore = scores.length ? Math.max(...scores) : 0
      const threatLevel = maxScore >= 80 ? 'critical' : maxScore >= 60 ? 'high' : maxScore >= 40 ? 'medium' : maxScore >= 20 ? 'low' : 'safe'
      const target = (emailData?.sender as string) || (headersData?.fromAnalysis as { address?: string })?.address || 'email-triage'

      const triage = {
        timestamp: new Date().toISOString(),
        target,
        email: emailData,
        headers: headersData,
        urlScans,
        maxScore,
        threatLevel,
        urlCount: urls.length,
      }

      setTriageResult(triage)

      const findings = [
        emailData ? `Email risk: ${emailData.riskScore}/100` : null,
        headersData ? `Header risk: ${headersData.riskScore}/100` : null,
        urlScans.length ? `${urlScans.length} URL(s) scanned` : null,
        urlScans.some(u => u.feedMatch && (u.feedMatch as { matched?: boolean }).matched) ? 'Threat feed match on URL' : null,
      ].filter(Boolean) as string[]

      await logAudit({ tool: 'TRIAGE', target, riskScore: maxScore, threatLevel, findings })

      saveTriageSession(triage)
      saveLastResult({
        type: 'TRIAGE',
        target,
        timestamp: triage.timestamp,
        riskScore: maxScore,
        threatLevel,
        findings,
        recommendations: [
          maxScore >= 60 ? 'Treat as confirmed phish — block sender and URLs' : 'Review findings before closing ticket',
          urlScans.length ? 'Investigate each extracted URL individually' : null,
          headersData && (headersData.riskScore as number) >= 50 ? 'Header anomalies detected — check for BEC/spoof' : null,
        ].filter(Boolean),
        iocs: {
          ips: (headersData?.iocs?.ips as string[]) || [],
          domains: [...new Set([emailData?.domain, ...((headersData?.iocs?.domains as string[]) || [])].filter(Boolean))] as string[],
          urls,
          hashes: [],
        },
        raw: triage,
      })
    } catch {
      setError('Full triage failed')
    }

    setTriageProgress('')
    setTriageLoading(false)
  }

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => {
      setInput(reader.result as string)
      setMode('file')
    }
    reader.readAsText(file)
  }

  const activeScore = (triageResult?.maxScore as number) ?? (result?.riskScore as number) ?? (headerResult?.riskScore as number)
  const scoreColor = activeScore >= 70 ? 'text-[#ff3366]' :
                     activeScore >= 50 ? 'text-[#ffcc00]' :
                     activeScore >= 30 ? 'text-[#ff9900]' : 'text-[#00ff88]'

  return (
    <div className="space-y-4">
      <div className="flex gap-1 flex-wrap">
        {(['manual', 'raw', 'file', 'headers'] as EmailMode[]).map(m => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`flex-1 min-w-[70px] py-2 rounded-lg text-xs font-bold uppercase ${mode === m ? 'bg-[#00ff88] text-black' : 'bg-[#111119] text-gray-400 border border-[#1a1a2e]'}`}
          >
            {m === 'manual' ? 'Domain' : m === 'raw' ? 'Paste' : m === 'file' ? 'Upload' : 'Headers'}
          </button>
        ))}
        <input ref={fileInputRef} type="file" accept=".eml,.msg,text/*" onChange={handleFile} className="hidden" />
      </div>

      {(mode === 'raw' || mode === 'file') && rawContent.trim() && (
        <button
          type="button"
          onClick={runFullTriage}
          disabled={triageLoading || loading}
          className="w-full py-3 rounded-lg bg-[#00ccff]/20 border border-[#00ccff]/50 text-[#00ccff] font-bold text-sm disabled:opacity-50"
        >
          {triageLoading ? triageProgress || 'Running full triage...' : '⚡ Full Triage — Email + Headers + All URLs'}
        </button>
      )}

      <form onSubmit={analyze} className="space-y-3">
        {mode === 'manual' && (
          <input
            value={senderEmail}
            onChange={e => setSenderEmail(e.target.value)}
            placeholder="sender@domain.com"
            className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
            disabled={loading || triageLoading}
          />
        )}
        {(mode === 'raw' || mode === 'headers') && (
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={mode === 'headers' ? 'Paste full email with headers (From, Received, Authentication-Results)...' : 'Paste raw email including headers...'}
            rows={8}
            className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-xs resize-y"
            disabled={loading || triageLoading}
          />
        )}
        {mode === 'file' && (
          <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-4 text-center">
            {fileName ? <p className="text-sm text-[#00ff88]">📎 {fileName}</p> : <p className="text-sm text-gray-500">No file selected</p>}
            <button type="button" onClick={() => fileInputRef.current?.click()} className="mt-2 text-xs text-gray-400 underline">Choose different file</button>
          </div>
        )}
        <button type="submit" disabled={loading || triageLoading || (mode === 'file' && !input) || (mode === 'manual' && !senderEmail) || ((mode === 'raw' || mode === 'headers') && !input)} className="w-full py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50">
          {loading ? 'Analyzing...' : mode === 'headers' ? 'Analyze Headers' : 'Analyze Email Risk'}
        </button>
      </form>

      {loading && <LoadingState message={mode === 'headers' ? 'Analyzing headers for spoofing indicators...' : 'Analyzing email for phishing indicators...'} />}

      {error && <ErrorState message={error} />}

      {triageResult && (
        <div className="bg-[#00ccff]/10 border border-[#00ccff]/40 rounded-lg p-4 space-y-2">
          <p className="text-xs font-bold text-[#00ccff] uppercase tracking-wide">Full Triage Complete</p>
          <p className="text-sm text-white">Combined risk: <span className={`font-bold ${scoreColor}`}>{triageResult.maxScore as number}/100</span> — {(triageResult.threatLevel as string).toUpperCase()}</p>
          <p className="text-xs text-gray-400">{(triageResult.urlCount as number) || 0} URL(s) scanned · saved to Report tab</p>
        </div>
      )}

      {headerResult && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wide">Header Analysis</p>
            <span className={`text-sm font-bold ${scoreColor}`}>{headerResult.riskScore as number}/100</span>
          </div>
          {(headerResult.threatIndicators as { severity?: string; description?: string }[])?.length > 0 && (
            <div className="space-y-1">
              {(headerResult.threatIndicators as { severity?: string; description?: string }[]).slice(0, 5).map((ind, i) => (
                <div key={i} className="text-xs text-gray-300">• {ind.description}</div>
              ))}
            </div>
          )}
          {Boolean(headerResult.replyToAnalysis) && !(headerResult.replyToAnalysis as { matchesFrom?: boolean })?.matchesFrom && (
            <p className="text-xs text-[#ff3366]">Reply-To mismatch detected — possible BEC</p>
          )}
        </div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 text-center">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Risk Score</p>
            <p className={`text-4xl font-bold ${scoreColor}`}>{result.riskScore as number}<span className="text-lg text-gray-500">/100</span></p>
            <p className={`text-sm font-bold uppercase mt-1 ${scoreColor}`}>{result.threatLevel as string}</p>
          </div>

          {Boolean(result.sender) && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">SENDER</p>
              <p className="text-sm font-mono text-white">{result.sender as string}</p>
            </div>
          )}

          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3 space-y-2">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Email Authentication</p>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div><p className="text-xs text-gray-400">SPF</p><p className={`text-sm font-bold ${(result.spf as { found?: boolean })?.found ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>{(result.spf as { found?: boolean })?.found ? '✓' : '✗'}</p></div>
              <div><p className="text-xs text-gray-400">DKIM</p><p className={`text-sm font-bold ${(result.dkim as { found?: boolean })?.found ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>{(result.dkim as { found?: boolean })?.found ? '✓' : '✗'}</p></div>
              <div><p className="text-xs text-gray-400">DMARC</p><p className={`text-sm font-bold ${(result.dmarc as { found?: boolean })?.found ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>{(result.dmarc as { found?: boolean })?.found ? '✓' : '✗'}</p></div>
            </div>
          </div>

          {Array.isArray(result.urls) && (result.urls as string[]).length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">URLs Found ({(result.urls as string[]).length})</p>
              <div className="space-y-0.5">
                {(result.urls as string[]).map(u => (
                  onInvestigate ? (
                    <button key={u} type="button" onClick={() => onInvestigate('url', u)} className="block text-xs font-mono text-[#00ccff] break-all text-left hover:underline">{u}</button>
                  ) : (
                    <div key={u} className="text-xs font-mono text-[#00ccff] break-all">{u}</div>
                  )
                ))}
              </div>
            </div>
          )}

          {(() => {
            const summary = generateExplanation(result)
            if (!summary) return null
            return (
              <div className={`border rounded-lg p-4 ${
                (result.riskScore as number) >= 70 ? 'bg-[#ff3366]/10 border-[#ff3366]/50' :
                (result.riskScore as number) >= 40 ? 'bg-[#ffcc00]/10 border-[#ffcc00]/30' :
                'bg-[#00ff88]/10 border-[#00ff88]/30'
              }`}>
                <p className="text-xs font-bold uppercase tracking-wide mb-2 text-gray-400">Analyst Summary</p>
                <p className="text-sm text-gray-200 leading-relaxed">{summary}</p>
              </div>
            )
          })()}
        </div>
      )}

      {!loading && !triageLoading && !error && !result && !headerResult && !triageResult && (
        <EmptyState icon="✉" title="No email analyzed yet" description="Enter a sender domain, paste raw email content, upload a file, or check headers to detect phishing indicators" />
      )}
    </div>
  )
}
