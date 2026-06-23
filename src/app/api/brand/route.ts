import { NextRequest, NextResponse } from 'next/server'

// Known brands for impersonation detection
const KNOWN_BRANDS = [
  'google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix',
  'facebook', 'instagram', 'twitter', 'linkedin', 'bankofamerica',
  'chase', 'wellsfargo', 'citi', 'americanexpress', 'venmo',
  'cashapp', 'coinbase', 'binance', 'dropbox', 'adobe', 'oracle',
  'salesforce', 'slack', 'zoom', 'github', 'gitlab', 'stripe',
  'shopify', 'walmart', 'target', 'fedex', 'ups', 'usps',
  'dhl', 'spotify', 'youtube', 'tiktok', 'snapchat', 'discord',
  'telegram', 'whatsapp', 'outlook', 'office365', 'live.com',
  'hotmail', 'yahoo', 'aol', 'protonmail', 'signal',
  'hhsc', 'medicaid', 'medicare', 'socialsecurity', 'irs',
]

// Homoglyph map — characters that look similar
const HOMOGLYPHS: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
  '@': 'a', '$': 's', '!': 'i', '|': 'l', 'rn': 'm', 'vv': 'w',
  'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i', 'é': 'e', 'è': 'e',
  'ê': 'e', 'ë': 'e', 'à': 'a', 'á': 'a', 'ä': 'a', 'â': 'a',
  'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'ú': 'u', 'ù': 'u',
  'ü': 'u', 'û': 'u', 'ñ': 'n', 'ç': 'c', 'š': 's', 'ž': 'z',
  'у': 'y', 'е': 'e', 'а': 'a', 'о': 'o', 'р': 'p', 'с': 'c',
  'х': 'x', 'к': 'k', 'м': 'm', 'т': 't', 'i': 'i', 'і': 'i',
}

function normalizeHomoglyphs(s: string): string {
  let result = s.toLowerCase()
  for (const [glyph, normal] of Object.entries(HOMOGLYPHS)) {
    result = result.replaceAll(glyph, normal)
  }
  return result
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length
  if (m === 0) return n
  if (n === 0) return m
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) dp[i][0] = i
  for (let j = 0; j <= n; j++) dp[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i-1] === b[j-1] ? 0 : 1
      dp[i][j] = Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost)
    }
  }
  return dp[m][n]
}

function similarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return 100
  const dist = levenshtein(a, b)
  return Math.round((1 - dist / maxLen) * 100)
}

export async function POST(request: NextRequest) {
  try {
    const { domain, url } = await request.json()
    const target = domain || (url ? (() => { try { return new URL(url).hostname } catch { return url } })() : '')

    if (!target) {
      return NextResponse.json({ error: 'Domain or URL required' }, { status: 400 })
    }

    const cleanDomain = target.toLowerCase().replace(/^www\./, '').split('.')[0]
    const fullDomain = target.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
    const normalized = normalizeHomoglyphs(cleanDomain)
    const normalizedFull = normalizeHomoglyphs(fullDomain)

    const matches: Array<{ brand: string; similarity: number; homoglyphUsed: boolean; distance: number }> = []

    for (const brand of KNOWN_BRANDS) {
      const directSim = similarity(cleanDomain, brand)
      const normSim = similarity(normalized, brand)
      // Also check if brand appears as substring (e.g. "paypal-login" contains "paypal")
      const containsBrand = normalized.includes(brand)
      const bestSim = Math.max(directSim, normSim, containsBrand ? 85 : 0)
      const usedHomoglyph = normSim > directSim

      if (bestSim >= 60) {
        matches.push({
          brand,
          similarity: bestSim,
          homoglyphUsed: usedHomoglyph,
          distance: levenshtein(normalized, brand),
        })
      }
    }

    matches.sort((a, b) => b.similarity - a.similarity)

    const isImpersonation = matches.length > 0 && matches[0].similarity >= 70
    const riskLevel = isImpersonation ? (matches[0].similarity >= 85 ? 'critical' : 'high') :
                      matches.length > 0 ? 'medium' : 'low'

    return NextResponse.json({
      domain: target,
      normalized,
      matches: matches.slice(0, 5),
      isImpersonation,
      riskLevel,
      homoglyphsDetected: matches.some(m => m.homoglyphUsed),
    })
  } catch (err) {
    console.error('Brand detection error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}