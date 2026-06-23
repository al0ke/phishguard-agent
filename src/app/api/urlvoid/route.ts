import { NextRequest, NextResponse } from 'next/server'

// URLVoid.com — free website reputation scanner
// No public JSON API (moved to APIVoid paid service)
// This route scrapes the URLVoid scan page and extracts results

const URLVOID_SCAN = 'https://www.urlvoid.com/scan/'

interface URLVoidResult {
  target: string
  scanUrl: string
  detected: boolean
  detections: number
  totalEngines: number
  detectionList: { engine: string; status: string }[]
  safe: boolean
  domainInfo: {
    domain?: string
    ip?: string
    serverLocation?: string
    domainAge?: string
    lastSeen?: string
    googleSafe?: boolean
  }
  error?: string
}

function extractDetections(html: string): { engine: string; status: string }[] {
  const detections: { engine: string; status: string }[] = []
  
  // URLVoid uses red/green status indicators in table rows
  // Look for detection entries: engine name + detected/clean status
  const rowRegex = /<tr[^>]*>[\s\S]*?<\/tr>/gi
  const rows = html.match(rowRegex) || []

  for (const row of rows) {
    // Extract engine name from the row
    const nameMatch = row.match(/<a[^>]*>([^<]+)<\/a>/i) || row.match(/<td[^>]*>([^<]+)<\/td>/i)
    // Look for "detected" or "clean" status
    const isRed = row.includes('class="red"') || row.includes('color:red') || row.includes('class="textred"')
    const isGreen = row.includes('class="green"') || row.includes('color:green') || row.includes('class="textgreen"')
    
    if (nameMatch) {
      const engine = nameMatch[1].trim()
      if (engine && !detections.find(d => d.engine === engine)) {
        detections.push({
          engine,
          status: isRed ? 'detected' : isGreen ? 'clean' : 'unknown',
        })
      }
    }
  }

  return detections.slice(0, 30)
}

function extractDomainInfo(html: string) {
  const info: Record<string, string | boolean> = {}

  // Extract IP address
  const ipMatch = html.match(/(?:IP Address|IP address)[:\s]*<\/[^>]+>\s*([0-9a-fA-F.:]+)/i)
  if (ipMatch) info.ip = ipMatch[1]

  // Extract domain
  const domainMatch = html.match(/(?:Domain|Domain name)[:\s]*<\/[^>]+>\s*([a-zA-Z0-9.\-]+)/i)
  if (domainMatch) info.domain = domainMatch[1]

  // Server location
  const locMatch = html.match(/(?:Server Location|Server location|Country)[:\s]*<\/[^>]+>\s*([a-zA-Z\s,]+)/i)
  if (locMatch) info.serverLocation = locMatch[1].trim()

  // Domain age / creation date
  const ageMatch = html.match(/(?:Domain Creation|Created|Registration)[:\s]*<\/[^>]+>\s*([0-9a-zA-Z\-\/ ]+)/i)
  if (ageMatch) info.domainAge = ageMatch[1].trim()

  // Google Safe Browsing
  info.googleSafe = !html.toLowerCase().includes('google safe browsing') || 
    html.toLowerCase().includes('google safe browsing') && 
    (html.toLowerCase().includes('this site is safe') || html.toLowerCase().includes('not suspicious'))

  return info
}

export async function POST(request: NextRequest) {
  try {
    const { target } = await request.json()

    if (!target || typeof target !== 'string') {
      return NextResponse.json({ error: 'URL or domain required' }, { status: 400 })
    }

    // Clean input — extract domain from URL if needed
    let domain = target.trim()
    try {
      if (domain.startsWith('http')) {
        domain = new URL(domain).hostname
      } else {
        domain = domain.replace(/^www\./, '').split('/')[0]
      }
    } catch {
      domain = domain.replace(/^https?:\/\//, '').split('/')[0]
    }

    const scanUrl = `${URLVOID_SCAN}${encodeURIComponent(domain)}/`

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 12000)

    const res = await fetch(scanUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.3809.100 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml',
      },
      signal: controller.signal,
    })

    clearTimeout(timer)

    if (!res.ok) {
      return NextResponse.json({ 
        error: `URLVoid returned ${res.status}. The service may be rate-limiting.`,
        target: domain,
      }, { status: 502 })
    }

    const html = await res.text()

    // Check if scan was rate-limited or blocked
    if (html.includes('rate limit') || html.includes('captcha') || html.length < 500) {
      return NextResponse.json({ 
        error: 'URLVoid is rate-limiting requests. Try again in a minute.',
        target: domain,
      }, { status: 429 })
    }

    const detections = extractDetections(html)
    const detectedList = detections.filter(d => d.status === 'detected')
    const domainInfo = extractDomainInfo(html)

    // Check overall verdict from page
    const isClean = html.toLowerCase().includes('this site is safe') || 
                    html.toLowerCase().includes('no detections') ||
                    detectedList.length === 0

    const result: URLVoidResult = {
      target: domain,
      scanUrl,
      detected: detectedList.length > 0,
      detections: detectedList.length,
      totalEngines: detections.length,
      detectionList: detectedList,
      safe: isClean,
      domainInfo: {
        domain: domainInfo.domain as string || domain,
        ip: domainInfo.ip as string,
        serverLocation: domainInfo.serverLocation as string,
        domainAge: domainInfo.domainAge as string,
        googleSafe: domainInfo.googleSafe as boolean,
      },
    }

    return NextResponse.json(result)
  } catch (err) {
    console.error('URLVoid API error:', err)
    return NextResponse.json({ error: 'Failed to scan via URLVoid. Service may be unavailable.' }, { status: 502 })
  }
}