'use client'

import { useState } from 'react'
import { LoadingState, ErrorState, EmptyState } from './StateViews'

interface OsintResult {
  url: string
  title: string | null
  description: string | null
  author?: string | null
  published?: string | null
  emails: string[]
  social: Record<string, string[]>
  externalDomains: string[]
  techStack: string[]
  linkCount: number
  markdown: string
  ogImage?: string | null
  error?: string
}

export default function OsintScraper({ onResult }: { onResult: (r: OsintResult) => void }) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<OsintResult | null>(null)

  const scrape = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    const targetUrl = url.trim().startsWith('http') ? url.trim() : `https://${url.trim()}`

    try {
      const res = await fetch('/api/osint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Scraping failed'); setLoading(false); return }
      setResult(data)
      onResult(data)
    } catch {
      setError('Network error')
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={scrape} className="space-y-2">
        <input
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://target.com"
          className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={!url.trim() || loading}
          className="w-full py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50"
        >
          {loading ? 'Scraping...' : 'Scrape Page'}
        </button>
      </form>

      {loading && <LoadingState message="Scraping page content and metadata..." />}

      {error && <ErrorState message={error} />}

      {result && (
        <div className="space-y-3">
          {result.title && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">TITLE</p>
              <p className="text-white text-sm">{result.title}</p>
            </div>
          )}

          {result.description && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">DESCRIPTION</p>
              <p className="text-gray-300 text-sm">{result.description.slice(0, 200)}</p>
            </div>
          )}

          {result.techStack?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">TECH STACK</p>
              <div className="flex flex-wrap gap-1">
                {result.techStack.map((t: string) => (
                  <span key={t} className="text-xs font-mono text-[#ff9900] bg-[#ff9900]/10 px-2 py-0.5 rounded">{t}</span>
                ))}
              </div>
            </div>
          )}

          {result.emails?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">EMAILS ({result.emails.length})</p>
              {result.emails.map((e: string) => (
                <div key={e} className="text-xs font-mono text-[#00ccff]">{e}</div>
              ))}
            </div>
          )}

          {Object.keys(result.social || {}).length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">SOCIAL</p>
              {Object.entries(result.social).map(([platform, links]) => (
                <div key={platform} className="text-xs mb-1">
                  <span className="text-gray-400 capitalize">{platform}: </span>
                  {links.map((l: string) => <a key={l} href={l} target="_blank" className="text-[#00ff88] font-mono ml-1">{l.slice(0, 50)}</a>)}
                </div>
              ))}
            </div>
          )}

          {result.externalDomains?.length > 0 && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">EXTERNAL DOMAINS ({result.externalDomains.length})</p>
              <div className="max-h-40 overflow-y-auto space-y-0.5">
                {result.externalDomains.map((d: string) => (
                  <div key={d} className="text-xs font-mono text-gray-300">{d}</div>
                ))}
              </div>
            </div>
          )}

          {result.markdown && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-2 uppercase tracking-wide">MARKDOWN PREVIEW</p>
              <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap overflow-x-auto max-h-60">{result.markdown.slice(0, 1000)}</pre>
          </div>
        )}
      </div>
    )}

      {!loading && !error && !result && (
        <EmptyState icon="🕵" title="No OSINT scrape yet" description="Enter a URL to extract page metadata, emails, social links, and tech stack" />
      )}
    </div>
  )
}
