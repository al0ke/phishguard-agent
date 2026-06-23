'use client'

import { useState, useRef, useCallback } from 'react'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

interface EmlResult {
  headers: Record<string, string | string[]>
  from: { address: string; displayName: string }
  to: string[]
  cc: string[]
  bcc: string[]
  replyTo?: string
  subject: string
  date: string
  messageId?: string
  returnPath?: string
  bodyText: string
  bodyHtml: string
  attachments: {
    filename: string
    contentType: string
    size: number
    content?: string
    md5Hash: string
  }[]
  urls: string[]
  ips: string[]
  domains: string[]
  receivedPath: {
    raw: string
    from?: string
    by?: string
    with?: string
    id?: string
    timestamp?: string
    ip?: string
    hostname?: string
  }[]
  authResults: {
    spf?: { result?: string; domain?: string }
    dkim?: { result?: string; domain?: string }
    dmarc?: { result?: string; policy?: string }
    raw?: string
  }
  riskScore: number
  threatLevel: string
}

type DragState = 'idle' | 'dragging' | 'loading' | 'done' | 'error'

export default function EmlParser({ onInvestigate }: AnalyzerShellProps) {
  const [dragState, setDragState] = useState<DragState>('idle')
  const [fileName, setFileName] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<EmlResult | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const analyzeFile = useCallback(async (file: File) => {
    setDragState('loading')
    setError(null)
    setResult(null)

    try {
      const text = await file.text()
      const res = await fetch('/api/eml', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Failed to parse .eml file')
        setDragState('error')
        return
      }
      setResult(data as EmlResult)
      setDragState('done')

      // ─── Audit logging (same pattern as EmailAnalyzer) ───
      const target = data.from?.address || fileName || 'eml-upload'
      const findings: string[] = []
      if (data.authResults?.spf?.result && data.authResults.spf.result !== 'pass')
        findings.push(`SPF: ${data.authResults.spf.result}`)
      if (data.authResults?.dkim?.result && data.authResults.dkim.result !== 'pass')
        findings.push(`DKIM: ${data.authResults.dkim.result}`)
      if (data.authResults?.dmarc?.result && data.authResults.dmarc.result !== 'pass')
        findings.push(`DMARC: ${data.authResults.dmarc.result}`)
      if (data.attachments?.length) findings.push(`${data.attachments.length} attachment(s)`)
      if (data.urls?.length > 3) findings.push(`${data.urls.length} URLs found`)
      if (data.domains?.length > 1) findings.push(`${data.domains.length} domains`)
      if (!data.authResults?.spf && !data.authResults?.dkim && !data.authResults?.dmarc)
        findings.push('No authentication results header')

      await logAudit({
        tool: 'EML_PARSER',
        target,
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        findings,
      })

      saveLastResult({
        type: 'EML_PARSER',
        target,
        timestamp: new Date().toISOString(),
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        findings,
        recommendations: [
          data.riskScore >= 70 ? 'Treat as confirmed phish — block sender and URLs' : null,
          data.attachments?.length ? 'Analyze all attachments for malware' : null,
          !data.authResults?.spf ? 'No SPF authentication result' : null,
          !data.authResults?.dkim ? 'No DKIM authentication result' : null,
        ].filter(Boolean) as string[],
        iocs: {
          ips: data.ips || [],
          domains: data.domains || [],
          urls: data.urls || [],
          hashes: data.attachments?.map((a: { md5Hash: string }) => a.md5Hash) || [],
        },
        raw: data,
      })
    } catch {
      setError('Network error — failed to reach /api/eml')
      setDragState('error')
    }
  }, [fileName])

  // ─── Drag & drop handlers ──────────────────────────────────────────────
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragState('dragging')
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (dragState !== 'loading' && dragState !== 'done') setDragState('idle')
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const file = e.dataTransfer.files?.[0]
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.eml') && file.type !== 'message/rfc822' && file.type !== 'text/plain') {
      setError('Please upload a .eml file')
      setDragState('error')
      return
    }
    setFileName(file.name)
    analyzeFile(file)
  }

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    analyzeFile(file)
  }

  const reset = () => {
    setResult(null)
    setError(null)
    setFileName(null)
    setDragState('idle')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  // ─── Score color helper ────────────────────────────────────────────────
  const scoreColor = (score: number) =>
    score >= 70 ? 'text-[#ff3366]' :
    score >= 50 ? 'text-[#ffcc00]' :
    score >= 30 ? 'text-[#ff9900]' : 'text-[#00ff88]'

  const authIcon = (result?: string) => {
    if (!result) return <span className="text-gray-500 text-sm">—</span>
    return result === 'pass'
      ? <span className="text-[#00ff88] text-sm font-bold">✓</span>
      : <span className="text-[#ff3366] text-sm font-bold">✗</span>
  }

  const authLabel = (result?: string) => {
    if (!result) return 'N/A'
    return result.toUpperCase()
  }

  // ─── Format helpers ──────────────────────────────────────────────────────
  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1048576).toFixed(2)} MB`
  }

  const shortenHash = (hash: string): string => {
    return hash ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : '—'
  }

  // ─── Render ──────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      {/* Upload Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => dragState !== 'loading' && fileInputRef.current?.click()}
        className={`
          relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all
          ${dragState === 'dragging' ? 'border-[#00ff88] bg-[#00ff88]/10' :
            dragState === 'loading' ? 'border-[#00ccff] bg-[#00ccff]/5' :
            dragState === 'error' ? 'border-[#ff3366]/50 bg-[#ff3366]/5' :
            'border-[#1a1a2e] bg-[#0a0a0f] hover:border-[#00ff88]/40 hover:bg-[#00ff88]/5'}
        `}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml,message/rfc822,text/plain"
          onChange={handleFileInput}
          className="hidden"
        />

        {dragState === 'loading' ? (
          <>
            <div className="inline-block w-8 h-8 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-3" />
            <p className="text-sm text-gray-400">Parsing {fileName}…</p>
          </>
        ) : dragState === 'done' && result ? (
          <>
            <p className="text-sm text-[#00ff88] mb-1">✓ Parsed: {fileName}</p>
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); reset() }}
              className="text-xs text-gray-400 underline hover:text-[#00ff88]"
            >
              Upload another file
            </button>
          </>
        ) : (
          <>
            <p className="text-3xl mb-2">📎</p>
            <p className="text-sm text-white font-bold mb-1">
              {dragState === 'dragging' ? 'Drop .eml file here' : 'Drag & drop .eml file'}
            </p>
            <p className="text-xs text-gray-500">or click to browse</p>
          </>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-3">
          <p className="text-[#ff3366] text-sm">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-3">
          {/* Risk Score */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 text-center">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Risk Score</p>
            <p className={`text-4xl font-bold ${scoreColor(result.riskScore)}`}>
              {result.riskScore}<span className="text-lg text-gray-500">/100</span>
            </p>
            <p className={`text-sm font-bold uppercase mt-1 ${scoreColor(result.riskScore)}`}>
              {result.threatLevel}
            </p>
          </div>

          {/* Email Metadata */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-2">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Email Metadata</p>
            <div className="space-y-1.5 text-xs">
              <div className="flex gap-2">
                <span className="text-gray-500 w-16 flex-shrink-0">From</span>
                <span className="font-mono text-white break-all">
                  {result.from.displayName ? `${result.from.displayName} <` : ''}
                  <span className="text-[#00ccff]">{result.from.address}</span>
                  {result.from.displayName ? '>' : ''}
                </span>
              </div>
              {result.to.length > 0 && (
                <div className="flex gap-2">
                  <span className="text-gray-500 w-16 flex-shrink-0">To</span>
                  <span className="font-mono text-white break-all">
                    {result.to.map((t, i) => (
                      <span key={i}>
                        {i > 0 && ', '}
                        <span className="text-[#00ccff]">{t}</span>
                      </span>
                    ))}
                  </span>
                </div>
              )}
              <div className="flex gap-2">
                <span className="text-gray-500 w-16 flex-shrink-0">Subject</span>
                <span className="font-mono text-white break-all">{result.subject || '(no subject)'}</span>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-500 w-16 flex-shrink-0">Date</span>
                <span className="font-mono text-gray-300 break-all">{result.date || '—'}</span>
              </div>
              {result.replyTo && (
                <div className="flex gap-2">
                  <span className="text-gray-500 w-16 flex-shrink-0">Reply-To</span>
                  <span className="font-mono text-[#ff9900] break-all">{result.replyTo}</span>
                </div>
              )}
              {result.returnPath && (
                <div className="flex gap-2">
                  <span className="text-gray-500 w-16 flex-shrink-0">Return-Path</span>
                  <span className="font-mono text-gray-300 break-all">{result.returnPath}</span>
                </div>
              )}
              {result.messageId && (
                <div className="flex gap-2">
                  <span className="text-gray-500 w-16 flex-shrink-0">Msg-ID</span>
                  <span className="font-mono text-gray-500 break-all">{result.messageId}</span>
                </div>
              )}
            </div>
          </div>

          {/* Authentication */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-2">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
              Authentication {result.authResults?.raw ? '' : '(none found)'}
            </p>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-2">
                <p className="text-xs text-gray-400 mb-1">SPF</p>
                <div className="flex items-center justify-center gap-1">
                  {authIcon(result.authResults?.spf?.result)}
                  <span className={`text-[10px] font-mono ${
                    result.authResults?.spf?.result === 'pass' ? 'text-[#00ff88]' :
                    result.authResults?.spf?.result ? 'text-[#ff3366]' : 'text-gray-500'
                  }`}>
                    {authLabel(result.authResults?.spf?.result)}
                  </span>
                </div>
              </div>
              <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-2">
                <p className="text-xs text-gray-400 mb-1">DKIM</p>
                <div className="flex items-center justify-center gap-1">
                  {authIcon(result.authResults?.dkim?.result)}
                  <span className={`text-[10px] font-mono ${
                    result.authResults?.dkim?.result === 'pass' ? 'text-[#00ff88]' :
                    result.authResults?.dkim?.result ? 'text-[#ff3366]' : 'text-gray-500'
                  }`}>
                    {authLabel(result.authResults?.dkim?.result)}
                  </span>
                </div>
              </div>
              <div className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-2">
                <p className="text-xs text-gray-400 mb-1">DMARC</p>
                <div className="flex items-center justify-center gap-1">
                  {authIcon(result.authResults?.dmarc?.result)}
                  <span className={`text-[10px] font-mono ${
                    result.authResults?.dmarc?.result === 'pass' ? 'text-[#00ff88]' :
                    result.authResults?.dmarc?.result ? 'text-[#ff3366]' : 'text-gray-500'
                  }`}>
                    {authLabel(result.authResults?.dmarc?.result)}
                  </span>
                </div>
              </div>
            </div>
            {result.authResults?.raw && (
              <details className="mt-2">
                <summary className="text-[10px] text-gray-500 cursor-pointer hover:text-[#00ccff]">
                  Show raw Authentication-Results
                </summary>
                <pre className="mt-1 text-[10px] font-mono text-gray-400 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-all">
                  {result.authResults.raw}
                </pre>
              </details>
            )}
          </div>

          {/* Received Path */}
          {result.receivedPath.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-3">
                Received Path ({result.receivedPath.length} hops)
              </p>
              <div className="space-y-1">
                {result.receivedPath.map((hop, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="text-gray-600 font-mono w-6 flex-shrink-0">{i + 1}.</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {hop.from && (
                          <span className="font-mono text-[#00ccff] break-all">
                            {hop.from}
                          </span>
                        )}
                        {hop.by && (
                          <>
                            <span className="text-gray-600">→</span>
                            <span className="font-mono text-[#00ff88] break-all">
                              {hop.by}
                            </span>
                          </>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-0.5 text-[10px] text-gray-500">
                        {hop.ip && <span className="font-mono">IP: {hop.ip}</span>}
                        {hop.with && <span className="font-mono">proto: {hop.with}</span>}
                        {hop.timestamp && <span className="font-mono">{hop.timestamp}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* URLs Found */}
          {result.urls.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
                URLs Found ({result.urls.length})
              </p>
              <div className="space-y-1">
                {result.urls.map((url, i) => (
                  <div key={i} className="flex items-center gap-2 group">
                    <span className="font-mono text-xs text-[#00ccff] break-all flex-1">{url}</span>
                    {onInvestigate && (
                      <button
                        type="button"
                        onClick={() => onInvestigate('url', url)}
                        className="text-[10px] px-2 py-1 rounded border border-[#1a1a2e] text-gray-400 hover:border-[#00ff88]/40 hover:text-[#00ff88] flex-shrink-0 transition-all"
                      >
                        Investigate
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attachments */}
          {result.attachments.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
                Attachments ({result.attachments.length})
              </p>
              <div className="space-y-1.5">
                {result.attachments.map((att, i) => (
                  <div key={i} className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-2.5">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs text-white break-all">{att.filename}</span>
                      <span className="text-[10px] text-gray-500 flex-shrink-0">{formatSize(att.size)}</span>
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-gray-500 font-mono">
                      <span>{att.contentType}</span>
                      <span>md5: {shortenHash(att.md5Hash)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Domains & IPs */}
          {(result.domains.length > 0 || result.ips.length > 0) && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 space-y-2">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Domains & IPs</p>
              {result.domains.length > 0 && (
                <div className="flex gap-2 items-start">
                  <span className="text-[10px] text-gray-500 w-12 flex-shrink-0 mt-0.5">Domains</span>
                  <div className="flex flex-wrap gap-1 flex-1">
                    {result.domains.map((d, i) => (
                      <span key={i} className="text-[10px] font-mono text-[#00ccff] bg-[#0a0a0f] border border-[#1a1a2e] rounded px-1.5 py-0.5">
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {result.ips.length > 0 && (
                <div className="flex gap-2 items-start">
                  <span className="text-[10px] text-gray-500 w-12 flex-shrink-0 mt-0.5">IPs</span>
                  <div className="flex flex-wrap gap-1 flex-1">
                    {result.ips.map((ip, i) => (
                      <span key={i} className="text-[10px] font-mono text-[#ff9900] bg-[#0a0a0f] border border-[#1a1a2e] rounded px-1.5 py-0.5">
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Body Preview */}
          {result.bodyText && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Body Preview (Plain Text)</p>
              <pre className="text-xs font-mono text-gray-300 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-3 overflow-auto max-h-80 whitespace-pre-wrap break-all">
                {result.bodyText.slice(0, 5000)}
                {result.bodyText.length > 5000 ? '\n\n… (truncated)' : ''}
              </pre>
            </div>
          )}

          {/* HTML Preview (collapsible) */}
          {result.bodyHtml && (
            <details className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <summary className="text-xs text-gray-400 uppercase tracking-wide cursor-pointer hover:text-[#00ccff]">
                HTML Body ({result.bodyHtml.length} chars)
              </summary>
              <pre className="mt-2 text-[10px] font-mono text-gray-400 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-3 overflow-auto max-h-60 whitespace-pre-wrap break-all">
                {result.bodyHtml.slice(0, 3000)}
                {result.bodyHtml.length > 3000 ? '\n\n… (truncated)' : ''}
              </pre>
            </details>
          )}

          {/* Raw Headers (collapsible) */}
          <details className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
            <summary className="text-xs text-gray-400 uppercase tracking-wide cursor-pointer hover:text-[#00ccff]">
              All Headers
            </summary>
            <pre className="mt-2 text-[10px] font-mono text-gray-400 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-3 overflow-auto max-h-60 whitespace-pre-wrap break-all">
              {JSON.stringify(result.headers, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}