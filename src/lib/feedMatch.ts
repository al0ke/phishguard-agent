interface FeedCache {
  openphishUrls: Set<string>
  openphishHosts: Set<string>
  urlhausUrls: Set<string>
  urlhausHosts: Set<string>
  fetchedAt: number
}

let cache: FeedCache | null = null
const CACHE_TTL_MS = 5 * 60 * 1000

async function loadFeedCache(): Promise<FeedCache> {
  if (cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) return cache

  const openphishUrls = new Set<string>()
  const openphishHosts = new Set<string>()
  const urlhausUrls = new Set<string>()
  const urlhausHosts = new Set<string>()

  try {
    const res = await fetch('https://openphish.com/feed.txt', {
      headers: { 'User-Agent': 'ThreatAnalyzer/2.1' },
    })
    if (res.ok) {
      const text = await res.text()
      for (const line of text.trim().split('\n')) {
        const u = line.trim()
        if (!u) continue
        openphishUrls.add(u.toLowerCase())
        try {
          openphishHosts.add(new URL(u).hostname.toLowerCase())
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }

  try {
    const res = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/', {
      headers: { 'User-Agent': 'ThreatAnalyzer/2.1' },
    })
    if (res.ok) {
      const text = await res.text()
      for (const line of text.trim().split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue
        const parts = line.split('","').map(p => p.replace(/"/g, ''))
        const u = (parts[2] || parts[1] || '').trim().toLowerCase()
        if (!u) continue
        urlhausUrls.add(u)
        try {
          urlhausHosts.add(new URL(u).hostname.toLowerCase())
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }

  cache = {
    openphishUrls,
    openphishHosts,
    urlhausUrls,
    urlhausHosts,
    fetchedAt: Date.now(),
  }
  return cache
}

export interface FeedMatchResult {
  matched: boolean
  sources: string[]
  openphish: boolean
  urlhaus: boolean
}

export async function checkFeedMatches(input: string): Promise<FeedMatchResult> {
  const feeds = await loadFeedCache()
  const sources: string[] = []
  let openphish = false
  let urlhaus = false

  const normalized = input.trim().toLowerCase()
  let hostname: string | null = null
  try {
    hostname = new URL(normalized.startsWith('http') ? normalized : `https://${normalized}`).hostname.toLowerCase()
  } catch {
    hostname = normalized.includes('.') ? normalized.split('/')[0] : null
  }

  if (feeds.openphishUrls.has(normalized) || (hostname && feeds.openphishHosts.has(hostname))) {
    openphish = true
    sources.push('OpenPhish')
  }

  if (feeds.urlhausUrls.has(normalized) || (hostname && feeds.urlhausHosts.has(hostname))) {
    urlhaus = true
    sources.push('URLhaus')
  }

  return { matched: sources.length > 0, sources, openphish, urlhaus }
}
