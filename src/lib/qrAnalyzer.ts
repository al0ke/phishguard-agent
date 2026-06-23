import jsQR from 'jsqr'

export interface QrAnalysisResult {
  data: string
  format: string
  version: number | null
  location: {
    topLeftCorner: { x: number; y: number }
    topRightCorner: { x: number; y: number }
    bottomLeftCorner: { x: number; y: number }
  }
  decoded: DecodedPayload
}

export interface DecodedPayload {
  type: 'url' | 'email' | 'phone' | 'sms' | 'wifi' | 'text' | 'vcard' | 'geo' | 'calendar' | 'unknown'
  value: string
  isSuspicious: boolean
  threatIndicators: ThreatIndicator[]
  parsedData?: Record<string, string>
}

export interface ThreatIndicator {
  type: 'suspicious_url' | 'shortened_url' | 'ip_address' | 'suspicious_tld' | 'credential_pattern' | 'suspicious_domain' | 'mismatched_display' | 'suspicious_keyword'
  severity: 'high' | 'medium' | 'low'
  description: string
}

const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'buzz', 'fit', 'kim', 'science', 'work', 'party', 'cricket', 'science', 'account', 'update', 'secure', 'verify', 'login', 'signin', 'bank', 'alert']
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'bit.do', 'mcaf.ee', 'soo.gd', 'shorturl.at', 'cutt.ly', 'tiny.cc', '短链接']
const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'account', 'update', 'secure', 'banking', 'password', 'credential', 'authenticate', 'confirm', 'alert', 'suspended', 'unusual', 'verify', 'validate']

export async function analyzeQrCode(imageData: ImageData): Promise<QrAnalysisResult | null> {
  try {
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert'
    })
    
    if (!code) {
      return null
    }
    
    const decoded = analyzeDecodedData(code.data)
    
    return {
      data: code.data,
      format: 'QR_CODE',
      version: null,
      location: {
        topLeftCorner: code.location.topLeftCorner,
        topRightCorner: code.location.topRightCorner,
        bottomLeftCorner: code.location.bottomLeftCorner
      },
      decoded
    }
  } catch (error) {
    console.error('QR analysis error:', error)
    return null
  }
}

export function analyzeQrFromCanvas(canvas: HTMLCanvasElement): Promise<QrAnalysisResult | null> {
  return new Promise((resolve) => {
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      resolve(null)
      return
    }
    
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
    analyzeQrCode(imageData).then(resolve)
  })
}

export async function analyzeQrFromImageFile(file: File): Promise<QrAnalysisResult | null> {
  return new Promise((resolve) => {
    const img = new Image()
    const url = URL.createObjectURL(file)
    
    img.onload = async () => {
      const canvas = document.createElement('canvas')
      canvas.width = img.width
      canvas.height = img.height
      const ctx = canvas.getContext('2d')
      
      if (!ctx) {
        URL.revokeObjectURL(url)
        resolve(null)
        return
      }
      
      ctx.drawImage(img, 0, 0)
      URL.revokeObjectURL(url)
      
      const result = await analyzeQrFromCanvas(canvas)
      resolve(result)
    }
    
    img.onerror = () => {
      URL.revokeObjectURL(url)
      resolve(null)
    }
    
    img.src = url
  })
}

function analyzeDecodedData(data: string): DecodedPayload {
  const threatIndicators: ThreatIndicator[] = []
  let type: DecodedPayload['type'] = 'unknown'
  let value = data
  let isSuspicious = false
  
  if (data.startsWith('http://') || data.startsWith('https://')) {
    type = 'url'
    value = data
    const urlAnalysis = analyzeUrl(data)
    threatIndicators.push(...urlAnalysis.indicators)
    isSuspicious = urlAnalysis.isSuspicious
  } else if (data.startsWith('mailto:')) {
    type = 'email'
    value = data.replace('mailto:', '')
    const emailThreats = analyzeEmailInQr(data)
    threatIndicators.push(...emailThreats)
    if (emailThreats.length > 0) isSuspicious = true
  } else if (data.startsWith('tel:')) {
    type = 'phone'
    value = data.replace('tel:', '')
  } else if (data.startsWith('sms:') || data.startsWith('smsto:')) {
    type = 'sms'
    const parts = data.split('?')
    value = parts[0].replace(/^smsto:|^sms:/, '')
  } else if (data.startsWith('WIFI:')) {
    type = 'wifi'
    value = data
    const wifiThreats = analyzeWifiQr(data)
    threatIndicators.push(...wifiThreats)
    if (wifiThreats.length > 0) isSuspicious = true
  } else if (data.startsWith('geo:')) {
    type = 'geo'
    value = data.replace('geo:', '')
  } else if (data.startsWith('BEGIN:VCARD')) {
    type = 'vcard'
    value = data
  } else if (data.startsWith('BEGIN:VEVENT')) {
    type = 'calendar'
    value = data
  } else if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$/.test(data)) {
    type = 'email'
    value = data
  } else if (/^[\w.+-]+@\w+\.\w+/.test(data) && data.includes('?')) {
    type = 'email'
    value = data.split('?')[0]
  } else {
    type = 'text'
    value = data
    
    if (looksLikePhishingText(data)) {
      threatIndicators.push({
        type: 'credential_pattern',
        severity: 'high',
        description: 'Text appears to be requesting credentials or sensitive information'
      })
      isSuspicious = true
    }
  }
  
  return { type, value, isSuspicious, threatIndicators }
}

function analyzeUrl(urlString: string): { indicators: ThreatIndicator[]; isSuspicious: boolean } {
  const indicators: ThreatIndicator[] = []
  let isSuspicious = false
  
  try {
    const url = new URL(urlString)
    const hostname = url.hostname.toLowerCase()
    
    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (hostname.includes(keyword)) {
        indicators.push({
          type: 'suspicious_keyword',
          severity: 'medium',
          description: `URL contains suspicious keyword: "${keyword}"`
        })
        isSuspicious = true
      }
    }
    
    if (SHORTENER_DOMAINS.some(d => hostname.includes(d))) {
      indicators.push({
        type: 'shortened_url',
        severity: 'medium',
        description: 'URL uses a URL shortening service - destination is obscured'
      })
      isSuspicious = true
    }
    
    const tld = hostname.split('.').pop()?.toLowerCase()
    if (tld && SUSPICIOUS_TLDS.includes(tld)) {
      indicators.push({
        type: 'suspicious_tld',
        severity: 'low',
        description: `URL uses a high-risk TLD (.${tld}) commonly associated with phishing`
      })
      isSuspicious = true
    }
    
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
    if (ipPattern.test(hostname)) {
      indicators.push({
        type: 'ip_address',
        severity: 'high',
        description: 'URL uses raw IP address instead of domain name - highly suspicious'
      })
      isSuspicious = true
    }
    
    const brandPatterns = [
      { brand: 'apple', pattern: /apple[-.]?id|icloud|apple\.com|app1e|4pple/i },
      { brand: 'microsoft', pattern: /microsoft|ms[-.]?365|office365|microsofit|micros0ft/i },
      { brand: 'google', pattern: /google|g00gle|g0ogle|goog1e|docs\.google/i },
      { brand: 'amazon', pattern: /amazon|amaz0n|amazn|paypa1|paypal/i },
      { brand: 'netflix', pattern: /netflix|netf1ix|nettflix/i },
      { brand: 'facebook', pattern: /facebook|faceb00k|facbook|facebook/i },
      { brand: 'instagram', pattern: /instagram|1nstagram|instagran/i },
      { brand: 'bank', pattern: /bank|chase|bofa|wellsfargo|capitalone|citibank/i }
    ]
    
    for (const { brand, pattern } of brandPatterns) {
      if (pattern.test(hostname) && !isLegitimateBrandDomain(hostname, brand)) {
        indicators.push({
          type: 'suspicious_domain',
          severity: 'high',
          description: `Possible ${brand} brand impersonation detected`
        })
        isSuspicious = true
        break
      }
    }
    
    const urlParams = url.searchParams
    if (urlParams.has('redirect') || urlParams.has('return') || urlParams.has('continue') || urlParams.has('url')) {
      const nextUrl = urlParams.get('redirect') || urlParams.get('return') || urlParams.get('continue') || urlParams.get('url')
      if (nextUrl && !nextUrl.startsWith('http')) {
        indicators.push({
          type: 'suspicious_url',
          severity: 'high',
          description: 'URL contains potentially spoofed redirect parameter'
        })
        isSuspicious = true
      }
    }
    
    const encodedParams = ['q', 'data', 'payload', 'param', 'token', 'key', 'email', 'user', 'id']
    for (const param of encodedParams) {
      if (urlParams.has(param)) {
        const val = urlParams.get(param)
        if (val && /%[0-9A-F]{2}/i.test(val)) {
          const decoded = decodeURIComponent(val)
          if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/.test(decoded)) {
            indicators.push({
              type: 'credential_pattern',
              severity: 'high',
              description: 'Encoded email address found in URL parameters'
            })
            isSuspicious = true
          }
        }
      }
    }
    
  } catch (e) {
    indicators.push({
      type: 'suspicious_url',
      severity: 'low',
      description: 'Unable to parse URL structure'
    })
  }
  
  return { indicators, isSuspicious }
}

function isLegitimateBrandDomain(hostname: string, brand: string): boolean {
  const legitimateDomains: Record<string, string[]> = {
    'apple': ['apple.com', 'icloud.com', 'apple.co'],
    'microsoft': ['microsoft.com', 'microsoftonline.com', 'office.com', 'windowsazure.com'],
    'google': ['google.com', 'googleapis.com', 'googleusercontent.com', 'goog', 'youtube.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazonaws.com', 'amazon.co'],
    'netflix': ['netflix.com', 'netflix.net', 'nflxvideo.net'],
    'facebook': ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com'],
    'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'capitalone.com', 'citibank.com']
  }
  
  const legitDomains = legitimateDomains[brand] || []
  return legitDomains.some(d => hostname === d || hostname.endsWith('.' + d))
}

function analyzeEmailInQr(data: string): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  
  const emailMatch = data.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/g)
  if (emailMatch) {
    for (const email of emailMatch) {
      const domain = email.split('@')[1]
      const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
      if (freeProviders.includes(domain.toLowerCase())) {
        indicators.push({
          type: 'mismatched_display',
          severity: 'low',
          description: `Email uses free provider (${domain}) which is unusual for official communications`
        })
      }
    }
  }
  
  return indicators
}

function analyzeWifiQr(data: string): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  
  const ssidMatch = data.match(/S:([^;]+);/)
  const passwordMatch = data.match(/P:([^;]+);/)
  
  if (ssidMatch) {
    const ssid = ssidMatch[1]
    if (ssid.toLowerCase().includes('free') || ssid.toLowerCase().includes('public') || ssid.toLowerCase().includes('wifi')) {
      indicators.push({
        type: 'suspicious_domain',
        severity: 'medium',
        description: 'QR code contains WiFi network that may be a rogue access point'
      })
    }
  }
  
  if (!passwordMatch) {
    indicators.push({
      type: 'suspicious_domain',
      severity: 'high',
      description: 'Open WiFi network (no password) - data can be intercepted'
    })
  }
  
  return indicators
}

function looksLikePhishingText(text: string): boolean {
  const phishingPatterns = [
    /urgent|act now|immediate/i,
    /verify your (account|identity|password)/i,
    /suspended (account|profile)/i,
    /confirm (your | )?(identity|account|details)/i,
    /click (here|link|bellow)/i,
    /update your (information|details|account)/i,
    /password (expired|reset|verify)/i,
    /security (alert|warning|notice)/i,
    /dear (customer|user|account holder|valued)/i
  ]
  
  return phishingPatterns.some(p => p.test(text))
}

export function calculateQrRiskScore(result: QrAnalysisResult): { score: number; level: 'critical' | 'high' | 'medium' | 'low' | 'safe' } {
  let score = 0
  
  const highSeverity = result.decoded.threatIndicators.filter(i => i.severity === 'high')
  const mediumSeverity = result.decoded.threatIndicators.filter(i => i.severity === 'medium')
  const lowSeverity = result.decoded.threatIndicators.filter(i => i.severity === 'low')
  
  score += highSeverity.length * 30
  score += mediumSeverity.length * 15
  score += lowSeverity.length * 5
  
  if (result.decoded.type === 'url') score += 5
  if (result.decoded.isSuspicious) score += 20
  
  if (result.data.length > 500) score += 5
  
  score = Math.min(score, 100)
  
  let level: 'critical' | 'high' | 'medium' | 'low' | 'safe' = 'safe'
  if (score >= 80) level = 'critical'
  else if (score >= 60) level = 'high'
  else if (score >= 40) level = 'medium'
  else if (score >= 20) level = 'low'
  
  return { score, level }
}
