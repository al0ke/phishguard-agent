import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'URL required' }, { status: 400 })
    }

    const targetUrl = url.startsWith('http') ? url : `https://${url}`

    // Follow redirects manually, collecting each hop
    const hops: Array<{ url: string; status: number; redirect: string | null }> = []
    let currentUrl = targetUrl
    const maxHops = 15

    for (let i = 0; i < maxHops; i++) {
      let res: Response
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 5000)
        res = await fetch(currentUrl, {
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
        })
        clearTimeout(timer)
      } catch {
        hops.push({ url: currentUrl, status: 0, redirect: null })
        break
      }

      const location = res.headers.get('location')
      hops.push({ url: currentUrl, status: res.status, redirect: location })

      if (res.status >= 300 && res.status < 400 && location) {
        // Resolve relative redirects
        if (location.startsWith('/')) {
          const parsed = new URL(currentUrl)
          currentUrl = `${parsed.origin}${location}`
        } else if (location.startsWith('http')) {
          currentUrl = location
        } else {
          const parsed = new URL(currentUrl)
          currentUrl = `${parsed.origin}/${location}`
        }
      } else {
        break
      }
    }

    // Also extract security headers from final response
    let securityHeaders: Record<string, string | null> = {}
    if (hops.length > 0) {
      const finalHop = hops[hops.length - 1]
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 5000)
        const finalRes = await fetch(finalHop.url, {
          redirect: 'follow',
          signal: controller.signal,
          headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
        })
        clearTimeout(timer)

        securityHeaders = {
          'strict-transport-security': finalRes.headers.get('strict-transport-security'),
          'content-security-policy': finalRes.headers.get('content-security-policy'),
          'x-frame-options': finalRes.headers.get('x-frame-options'),
          'x-content-type-options': finalRes.headers.get('x-content-type-options'),
          'x-xss-protection': finalRes.headers.get('x-xss-protection'),
          'referrer-policy': finalRes.headers.get('referrer-policy'),
          'permissions-policy': finalRes.headers.get('permissions-policy'),
        }
      } catch { /* non-fatal */ }
    }

    const hasSecurityIssues = !securityHeaders['strict-transport-security'] ||
                               !securityHeaders['content-security-policy'] ||
                               !securityHeaders['x-frame-options']

    // Calculate risk from redirects + headers
    let riskScore = 0
    const findings: string[] = []

    if (hops.length > 3) { riskScore += 20; findings.push(`${hops.length} redirects — excessive redirection chain`) }
    else if (hops.length > 1) { riskScore += 5; findings.push(`${hops.length} redirects`) }

    if (!securityHeaders['strict-transport-security']) { riskScore += 15; findings.push('HSTS header missing') }
    else findings.push('HSTS header present')

    if (!securityHeaders['content-security-policy']) { riskScore += 15; findings.push('CSP header missing') }
    else findings.push('CSP header present')

    if (!securityHeaders['x-frame-options']) { riskScore += 10; findings.push('X-Frame-Options missing') }
    else findings.push('X-Frame-Options present')

    if (!securityHeaders['x-content-type-options']) { riskScore += 5; findings.push('X-Content-Type-Options missing') }

    // Check for suspicious redirect patterns
    for (const hop of hops) {
      try {
        const parsed = new URL(hop.url)
        if (parsed.hostname.match(/^(\d{1,3}\.){3}\d{1,3}$/)) { riskScore += 15; findings.push(`Redirects to raw IP: ${parsed.hostname}`) }
        if (parsed.hostname.includes('bit.ly') || parsed.hostname.includes('tinyurl') || parsed.hostname.includes('t.co')) {
          riskScore += 10; findings.push(`Uses URL shortener: ${parsed.hostname}`)
        }
      } catch { /* skip */ }
    }

    riskScore = Math.min(riskScore, 100)

    return NextResponse.json({
      originalUrl: targetUrl,
      finalUrl: hops.length > 0 ? hops[hops.length - 1].url : targetUrl,
      hops,
      hopCount: hops.length,
      securityHeaders,
      hasSecurityIssues,
      riskScore,
      findings,
      threatLevel: riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'medium' : 'low',
    })
  } catch (err) {
    console.error('Redirect trace error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}