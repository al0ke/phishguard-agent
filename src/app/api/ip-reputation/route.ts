import { NextRequest, NextResponse } from 'next/server'

// IP reputation check via ip-api.com (free tier, no API key required).
// Docs: https://ip-api.com/docs/api:json — free tier is HTTP-only and rate
// limited to 45 requests/minute per source IP.

interface IpApiResponse {
  status: 'success' | 'fail'
  message?: string
  query: string
  continent?: string
  continentCode?: string
  country?: string
  countryCode?: string
  region?: string
  regionName?: string
  city?: string
  district?: string
  zip?: string
  lat?: number
  lon?: number
  timezone?: string
  isp?: string
  org?: string
  as?: string
  asname?: string
  reverse?: string
  mobile?: boolean
  proxy?: boolean
  hosting?: boolean
}

export interface IpReputationResult {
  ip: string
  isValid: boolean
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
  reputation: 'malicious' | 'suspicious' | 'clean'
  flags: {
    proxy: boolean
    hosting: boolean
    mobile: boolean
  }
  location: {
    country: string | null
    countryCode: string | null
    region: string | null
    city: string | null
    lat: number | null
    lon: number | null
    timezone: string | null
  }
  network: {
    isp: string | null
    org: string | null
    asn: string | null
    asname: string | null
    reverseDns: string | null
  }
  signals: string[]
  source: string
}

// RFC 1918 / loopback / link-local ranges — ip-api.com rejects these as "private range"
const PRIVATE_IPV4_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
]

const HIGH_RISK_COUNTRY_CODES = ['RU', 'CN', 'KP', 'IR']

function isValidIPv4(ip: string): boolean {
  const parts = ip.trim().split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
}

function isValidIPv6(ip: string): boolean {
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(ip.trim())
}

function isPrivateIPv4(ip: string): boolean {
  return PRIVATE_IPV4_RANGES.some((re) => re.test(ip))
}

async function fetchIpApi(ip: string): Promise<IpApiResponse | null> {
  const fields = [
    'status', 'message', 'continent', 'continentCode', 'country', 'countryCode',
    'region', 'regionName', 'city', 'district', 'zip', 'lat', 'lon', 'timezone',
    'isp', 'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'query',
  ].join(',')

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 6000)
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'PhishGuard-Agent/1.0' },
    })
    if (!res.ok) return null
    return (await res.json()) as IpApiResponse
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

function buildResult(ip: string, data: IpApiResponse): IpReputationResult {
  const signals: string[] = []
  let score = 0

  const proxy = Boolean(data.proxy)
  const hosting = Boolean(data.hosting)
  const mobile = Boolean(data.mobile)

  if (proxy) {
    score += 40
    signals.push('IP is a known proxy/VPN/Tor exit node')
  }
  if (hosting) {
    score += 20
    signals.push('IP belongs to a hosting/datacenter provider — unusual for a real end user')
  }
  if (data.countryCode && HIGH_RISK_COUNTRY_CODES.includes(data.countryCode)) {
    score += 15
    signals.push(`Located in a region frequently associated with abuse (${data.country || data.countryCode})`)
  }
  if (!data.isp && !data.org) {
    score += 10
    signals.push('No ISP/organization information available')
  }

  score = Math.min(score, 100)

  const riskLevel: IpReputationResult['riskLevel'] =
    score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : score > 0 ? 'low' : 'safe'
  const reputation: IpReputationResult['reputation'] =
    score >= 60 ? 'malicious' : score >= 30 ? 'suspicious' : 'clean'

  if (signals.length === 0) signals.push('No abuse indicators found from available signals')

  return {
    ip,
    isValid: true,
    riskScore: score,
    riskLevel,
    reputation,
    flags: { proxy, hosting, mobile },
    location: {
      country: data.country || null,
      countryCode: data.countryCode || null,
      region: data.regionName || data.region || null,
      city: data.city || null,
      lat: data.lat ?? null,
      lon: data.lon ?? null,
      timezone: data.timezone || null,
    },
    network: {
      isp: data.isp || null,
      org: data.org || null,
      asn: data.as || null,
      asname: data.asname || null,
      reverseDns: data.reverse || null,
    },
    signals,
    source: 'ip-api.com',
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => null)
    const rawIp = body?.ip

    if (!rawIp || typeof rawIp !== 'string') {
      return NextResponse.json({ error: 'IP address is required' }, { status: 400 })
    }

    const ip = rawIp.trim()

    if (!isValidIPv4(ip) && !isValidIPv6(ip)) {
      return NextResponse.json({ error: 'Invalid IP address format' }, { status: 400 })
    }

    if (isPrivateIPv4(ip)) {
      return NextResponse.json(
        { error: 'Private/reserved IP addresses cannot be looked up against public reputation databases' },
        { status: 400 }
      )
    }

    const data = await fetchIpApi(ip)

    if (!data) {
      return NextResponse.json(
        { error: 'IP reputation lookup timed out or the upstream service is unavailable' },
        { status: 502 }
      )
    }

    if (data.status !== 'success') {
      return NextResponse.json(
        { error: data.message || 'IP reputation lookup failed for this address' },
        { status: 400 }
      )
    }

    return NextResponse.json(buildResult(ip, data))
  } catch (err) {
    console.error('IP reputation route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}
