'use client'

import { useState, useEffect, useMemo } from 'react'

interface FeedEntry {
  cve?: string
  vendor?: string
  product?: string
  name?: string
  date?: string
  severity?: string
  url?: string
  domain?: string | null
  path?: string | null
  status?: string
  threat?: string | null
}

interface FeedBucket {
  count?: number
  title?: string
  recent?: FeedEntry[]
  error?: string
}

type FeedsData = Partial<Record<'cisa' | 'openphish' | 'urlhaus', FeedBucket>>

export default function ThreatFeeds() {
  const [loading, setLoading] = useState(true)
  const [feeds, setFeeds] = useState<FeedsData | null>(null)
  const [activeFeed, setActiveFeed] = useState<'cisa' | 'openphish' | 'urlhaus'>('cisa')
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetch('/api/feeds')
      .then(r => r.json())
      .then(d => { setFeeds(d); setLoading(false) })
      .catch(() => { setLoading(false) })
  }, [])

  const feedData = feeds?.[activeFeed]

  // Filter entries based on search
  const filteredEntries = useMemo(() => {
    if (!feedData?.recent || !search.trim()) return feedData?.recent || []
    const q = search.toLowerCase().trim()
    return feedData.recent.filter((item: FeedEntry) => {
      if (activeFeed === 'cisa') {
        return item.cve?.toLowerCase().includes(q) ||
               item.vendor?.toLowerCase().includes(q) ||
               item.product?.toLowerCase().includes(q) ||
               item.name?.toLowerCase().includes(q)
      }
      if (activeFeed === 'openphish') {
        return item.url?.toLowerCase().includes(q) || item.domain?.toLowerCase().includes(q)
      }
      if (activeFeed === 'urlhaus') {
        return item.url?.toLowerCase().includes(q) || item.threat?.toLowerCase().includes(q)
      }
      return false
    })
  }, [feedData, search, activeFeed])

  const feedLabels: Record<string, { name: string; color: string; desc: string; placeholder: string }> = {
    cisa: { name: 'CISA KEV', color: '#ff3366', desc: 'Known Exploited Vulnerabilities', placeholder: 'Search CVE, vendor, product...' },
    openphish: { name: 'OpenPhish', color: '#ffcc00', desc: 'Active phishing URLs', placeholder: 'Search domain or URL...' },
    urlhaus: { name: 'URLhaus', color: '#00ccff', desc: 'Malware URL distribution', placeholder: 'Search URL or threat...' },
  }

  if (loading) {
    return (
      <div className="space-y-3">
        {[1, 2, 3].map(i => (
          <div key={i} className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 animate-pulse">
            <div className="h-4 w-32 bg-[#1a1a2e] rounded mb-2" />
            <div className="h-3 w-full bg-[#1a1a2e] rounded mb-1" />
            <div className="h-3 w-2/3 bg-[#1a1a2e] rounded" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Feed selector */}
      <div className="flex gap-2">
        {(['cisa', 'openphish', 'urlhaus'] as const).map(feed => (
          <button
            key={feed}
            onClick={() => { setActiveFeed(feed); setSearch('') }}
            className={`flex-1 py-2.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${
              activeFeed === feed
                ? 'bg-[#00ff88] text-black'
                : 'bg-[#111119] text-gray-400 border border-[#1a1a2e] hover:text-white'
            }`}
          >
            {feedLabels[feed].name}
          </button>
        ))}
      </div>

      {/* Search bar */}
      <input
        value={search}
        onChange={e => setSearch(e.target.value)}
        placeholder={feedLabels[activeFeed].placeholder}
        className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
      />

      {/* Feed summary */}
      {feedData && !feedData.error && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <div>
              <p className="text-sm font-bold" style={{ color: feedLabels[activeFeed].color }}>{feedLabels[activeFeed].name}</p>
              <p className="text-xs text-gray-400">{feedLabels[activeFeed].desc}</p>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-white">{feedData.count?.toLocaleString() || '?'}</p>
              <p className="text-xs text-gray-500">total entries</p>
            </div>
          </div>
          {search && (
            <p className="text-xs text-gray-500 mt-1">{filteredEntries.length} matching results</p>
          )}
        </div>
      )}

      {/* Feed entries */}
      {filteredEntries.length > 0 && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
            {search ? `Search Results (${filteredEntries.length})` : 'Recent Entries'}
          </p>
          <div className="space-y-1.5 max-h-80 overflow-y-auto">
            {filteredEntries.map((item: FeedEntry, i: number) => (
              <div key={i} className="border-b border-[#1a1a2e] pb-1.5 mb-1.5 last:border-0">
                {activeFeed === 'cisa' && (
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-[#ff3366]">{item.cve}</span>
                      {item.severity === 'critical' && <span className="text-[10px] bg-[#ff3366]/20 text-[#ff3366] px-1 rounded">CRITICAL</span>}
                    </div>
                    <p className="text-xs text-gray-300 mt-0.5">{item.vendor} {item.product}</p>
                    <p className="text-xs text-gray-500">{item.name}</p>
                    {item.date && <p className="text-[10px] text-gray-600">Added: {item.date}</p>}
                  </div>
                )}
                {activeFeed === 'openphish' && (
                  <div>
                    <p className="text-xs font-mono text-[#ffcc00] break-all">{item.url}</p>
                    <p className="text-[10px] text-gray-500">{item.domain}</p>
                  </div>
                )}
                {activeFeed === 'urlhaus' && (
                  <div>
                    <p className="text-xs font-mono text-[#00ccff] break-all">{item.url}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      {item.threat && <span className="text-[10px] text-[#ff3366]">{item.threat}</span>}
                      {item.status && <span className="text-[10px] text-gray-500">{item.status}</span>}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {search && filteredEntries.length === 0 && !feedData?.error && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <p className="text-sm text-gray-400">No matches for &quot;{search}&quot;</p>
        </div>
      )}

      {feedData?.error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-3 text-[#ff3366] text-sm">
          {feedData.error}
        </div>
      )}
    </div>
  )
}