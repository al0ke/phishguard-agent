export interface ParsedEmail {
  raw: string
  headers: Record<string, string>
  analysis: {
    authResults: AuthResult[]
    securityFlags: SecurityFlag[]
    suspiciousIndicators: SuspiciousIndicator[]
    routingPath: RoutingHop[]
    fromAnalysis: FromAnalysis
    replyToAnalysis: ReplyToAnalysis | null
    dateAnalysis: DateAnalysis
  }
}

export interface AuthResult {
  method: string
  result: 'pass' | 'fail' | 'none' | 'softfail' | 'policy' | 'neutral' | 'temperror' | 'permerror'
  severity: 'pass' | 'warning' | 'fail'
}

export interface SecurityFlag {
  type: 'dkim' | 'spf' | 'dmarc' | 'arc' | 'bimi'
  present: boolean
  value: string | null
  status: 'pass' | 'fail' | 'none' | 'warning'
}

export interface SuspiciousIndicator {
  type: 'mismatch_from' | 'suspicious_received' | 'hidden_recipients' | 'excessive_hops' | 'open_relay' | 'generic_replyto' | 'date_anomaly' | 'missing_auth' | 'spoofed_header'
  severity: 'high' | 'medium' | 'low'
  description: string
  rawValue?: string
}

export interface RoutingHop {
  number: number
  from: string
  by: string
  with: string
  ip: string | null
  delay: string | null
  timestamp: string
}

export interface FromAnalysis {
  displayName: string | null
  address: string
  domain: string
  domainAge: string | null
  domainReputation: 'legitimate' | 'suspicious' | 'malicious' | 'unknown'
  freeProvider: boolean
  disposableProvider: boolean
}

export interface ReplyToAnalysis {
  address: string
  domain: string
  matchesFrom: boolean
}

export interface DateAnalysis {
  sent: string | null
  received: string | null
  timezone: string | null
  anomaly: 'none' | 'future_date' | 'distant_past' | 'clock_drift' | 'missing'
}

export function parseEmailHeaders(emailContent: string): ParsedEmail {
  const headers: Record<string, string> = {}
  const lines = emailContent.split(/\r?\n/)
  
  let currentKey = ''
  let currentValue = ''
  let inHeader = true
  
  for (const line of lines) {
    if (inHeader && line === '') {
      if (currentKey) {
        headers[currentKey.toLowerCase()] = currentValue.trim()
      }
      inHeader = false
      continue
    }
    
    if (inHeader) {
      if (line.match(/^[^\s:]+:/)) {
        if (currentKey) {
          headers[currentKey.toLowerCase()] = currentValue.trim()
        }
        const colonIndex = line.indexOf(':')
        currentKey = line.substring(0, colonIndex).trim()
        currentValue = line.substring(colonIndex + 1)
      } else if (currentKey && line.match(/^\s/)) {
        currentValue += ' ' + line
      } else {
        if (currentKey) {
          headers[currentKey.toLowerCase()] = currentValue.trim()
        }
        currentKey = ''
        currentValue = ''
      }
    }
  }
  
  if (currentKey && inHeader) {
    headers[currentKey.toLowerCase()] = currentValue.trim()
  }

  const authResults = parseAuthResults(headers['authentication-results'] || headers['authentication-results'] || '')
  const securityFlags = extractSecurityFlags(headers)
  const routingPath = parseReceivedHeaders(headers)
  const fromAnalysis = analyzeFrom(headers['from'] || '')
  const replyToAnalysis = headers['reply-to'] ? analyzeReplyTo(headers['reply-to'], fromAnalysis.address) : null
  const dateAnalysis = analyzeDate(headers['date'] || '', headers['received'] || '')
  
  const suspiciousIndicators = findSuspiciousIndicators(
    headers,
    authResults,
    securityFlags,
    fromAnalysis,
    replyToAnalysis,
    dateAnalysis,
    routingPath
  )
  
  return {
    raw: emailContent,
    headers,
    analysis: {
      authResults,
      securityFlags,
      suspiciousIndicators,
      routingPath,
      fromAnalysis,
      replyToAnalysis,
      dateAnalysis
    }
  }
}

function parseAuthResults(authHeader: string): AuthResult[] {
  const results: AuthResult[] = []
  if (!authHeader) return results
  
  const mechanisms = authHeader.matchAll(/(?:dkim|spf|dmarc|arc|bimi)=([^;\s]+)/gi)
  for (const match of mechanisms) {
    const method = match[1].toLowerCase().split('=')[0] || match[1]
    const result = match[2]?.trim() || match[1].trim()
    
    let severity: AuthResult['severity'] = 'pass'
    if (result === 'fail' || result === 'permerror') severity = 'fail'
    else if (result === 'softfail' || result === 'temperror' || result === 'none') severity = 'warning'
    
    results.push({
      method: method.includes('=') ? method.split('=')[0] : method,
      result: normalizeAuthResult(result),
      severity
    })
  }
  
  return results
}

function normalizeAuthResult(result: string): AuthResult['result'] {
  const lower = result.toLowerCase()
  if (lower === 'pass') return 'pass'
  if (lower === 'fail') return 'fail'
  if (lower === 'softfail') return 'softfail'
  if (lower === 'none') return 'none'
  if (lower === 'neutral') return 'neutral'
  if (lower === 'temperror') return 'temperror'
  if (lower === 'permerror') return 'permerror'
  if (lower === 'policy') return 'policy'
  return 'none'
}

function extractSecurityFlags(headers: Record<string, string>): SecurityFlag[] {
  const flags: SecurityFlag[] = []
  
  const dkimHeader = headers['dkim-signature'] || headers['dkim'] || ''
  flags.push({
    type: 'dkim',
    present: !!dkimHeader,
    value: dkimHeader ? extractDkimResult(headers) : null,
    status: getDkimStatus(headers)
  })
  
  const spfResult = headers['authentication-results']?.match(/spf=(pass|fail|softfail|none)/i)
  flags.push({
    type: 'spf',
    present: !!spfResult,
    value: spfResult ? spfResult[1] : null,
    status: normalizeStatus(spfResult?.[1])
  })
  
  const dmarcResult = headers['authentication-results']?.match(/dmarc=(pass|fail|none)/i)
  flags.push({
    type: 'dmarc',
    present: !!dmarcResult,
    value: dmarcResult ? dmarcResult[1] : null,
    status: normalizeStatus(dmarcResult?.[1])
  })
  
  const arcResult = headers['authentication-results']?.match(/arc=(pass|fail|none)/i)
  flags.push({
    type: 'arc',
    present: !!arcResult,
    value: arcResult ? arcResult[1] : null,
    status: normalizeStatus(arcResult?.[1])
  })
  
  return flags
}

function extractDkimResult(headers: Record<string, string>): string {
  const auth = headers['authentication-results'] || ''
  const dkimMatch = auth.match(/dkim=(pass|fail|none)/i)
  return dkimMatch ? dkimMatch[1] : 'unknown'
}

function getDkimStatus(headers: Record<string, string>): SecurityFlag['status'] {
  const auth = headers['authentication-results'] || ''
  const dkimMatch = auth.match(/dkim=(pass|fail|none)/i)
  return normalizeStatus(dkimMatch?.[1])
}

function normalizeStatus(status?: string): SecurityFlag['status'] {
  if (!status) return 'none'
  const lower = status.toLowerCase()
  if (lower === 'pass') return 'pass'
  if (lower === 'fail' || lower === 'permerror') return 'fail'
  return 'none'
}

function parseReceivedHeaders(headers: Record<string, string>): RoutingHop[] {
  const hops: RoutingHop[] = []
  let hopNumber = 1
  
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith('received')) {
      const parts = value.split(';')
      const timestamp = parts[parts.length - 1]?.trim() || ''
      const serverInfo = parts.slice(0, -1).join(';').trim()
      
      const fromMatch = serverInfo.match(/from\s+([^\s]+)/i)
      const byMatch = serverInfo.match(/by\s+([^\s]+)/i)
      const withMatch = serverInfo.match(/with\s+([^\s]+)/i)
      const ipMatch = serverInfo.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/)
      
      hops.push({
        number: hopNumber++,
        from: fromMatch ? fromMatch[1] : 'unknown',
        by: byMatch ? byMatch[1] : 'unknown',
        with: withMatch ? withMatch[1] : 'unknown',
        ip: ipMatch ? ipMatch[1] : null,
        delay: null,
        timestamp
      })
    }
  }
  
  return hops
}

function analyzeFrom(fromHeader: string): FromAnalysis {
  const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/([^\s<>]+@[^\s<>]+)/)
  const displayMatch = fromHeader.match(/"?([^"<]+)"?\s*</)
  
  const address = emailMatch ? emailMatch[1] : fromHeader
  const domain = address.split('@')[1] || ''
  const displayName = displayMatch ? displayMatch[1].trim() : null
  
  const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'mail.com', 'protonmail.com']
  const disposableProviders = ['tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com', '10minutemail.com', 'fakeinbox.com', 'trashmail.com']
  
  return {
    displayName,
    address,
    domain,
    domainAge: null,
    domainReputation: 'unknown',
    freeProvider: freeProviders.includes(domain.toLowerCase()),
    disposableProvider: disposableProviders.includes(domain.toLowerCase())
  }
}

function analyzeReplyTo(replyToHeader: string, fromAddress: string): ReplyToAnalysis | null {
  const emailMatch = replyToHeader.match(/<([^>]+)>/) || replyToHeader.match(/([^\s<>]+@[^\s<>]+)/)
  if (!emailMatch) return null
  
  const address = emailMatch[1]
  const domain = address.split('@')[1] || ''
  
  return {
    address,
    domain,
    matchesFrom: domain === fromAddress.split('@')[1]
  }
}

function analyzeDate(dateHeader: string, receivedHeader: string): DateAnalysis {
  const sent = dateHeader || null
  
  const receivedMatch = receivedHeader?.match(/;\s*([^\n;]+)$/)
  const received = receivedMatch ? receivedMatch[1].trim() : null
  
  const timezoneMatch = dateHeader?.match(/([+-]\d{4}|[A-Z]{2,4}T|[A-Z]{2,4}ST)/)
  const timezone = timezoneMatch ? timezoneMatch[1] : null
  
  let anomaly: DateAnalysis['anomaly'] = 'none'
  
  if (dateHeader) {
    try {
      const date = new Date(dateHeader)
      const now = new Date()
      
      if (date > now) anomaly = 'future_date'
      else if (date < new Date('1990-01-01')) anomaly = 'distant_past'
    } catch {
      anomaly = 'missing'
    }
  } else {
    anomaly = 'missing'
  }
  
  return { sent, received, timezone, anomaly }
}

function findSuspiciousIndicators(
  headers: Record<string, string>,
  authResults: AuthResult[],
  securityFlags: SecurityFlag[],
  fromAnalysis: FromAnalysis,
  replyToAnalysis: ReplyToAnalysis | null,
  dateAnalysis: DateAnalysis,
  routingPath: RoutingHop[]
): SuspiciousIndicator[] {
  const indicators: SuspiciousIndicator[] = []
  
  const spfFail = authResults.find(a => a.method.toLowerCase() === 'spf' && a.result === 'fail')
  const dkimFail = authResults.find(a => a.method.toLowerCase() === 'dkim' && a.result === 'fail')
  const dmarcFail = authResults.find(a => a.method.toLowerCase() === 'dmarc' && a.result === 'fail')
  
  if (spfFail || dkimFail || dmarcFail) {
    indicators.push({
      type: 'spoofed_header',
      severity: 'high',
      description: 'Email failed authentication checks - possible spoofing',
      rawValue: `SPF: ${spfFail?.result || 'none'}, DKIM: ${dkimFail?.result || 'none'}, DMARC: ${dmarcFail?.result || 'none'}`
    })
  }
  
  if (replyToAnalysis && !replyToAnalysis.matchesFrom) {
    indicators.push({
      type: 'generic_replyto',
      severity: 'medium',
      description: `Reply-To domain (${replyToAnalysis.domain}) differs from From domain (${fromAnalysis.domain})`,
      rawValue: replyToAnalysis.address
    })
  }
  
  if (dateAnalysis.anomaly === 'future_date') {
    indicators.push({
      type: 'date_anomaly',
      severity: 'medium',
      description: 'Email date is in the future - possible timestamp manipulation'
    })
  }
  
  if (dateAnalysis.anomaly === 'missing') {
    indicators.push({
      type: 'date_anomaly',
      severity: 'low',
      description: 'Missing or malformed date header'
    })
  }
  
  if (routingPath.length > 10) {
    indicators.push({
      type: 'excessive_hops',
      severity: 'medium',
      description: `Unusual routing path with ${routingPath.length} hops`,
      rawValue: `${routingPath.length} hops`
    })
  }
  
  const missingAuth = securityFlags.filter(f => !f.present)
  if (missingAuth.length > 0) {
    indicators.push({
      type: 'missing_auth',
      severity: 'low',
      description: `Missing authentication: ${missingAuth.map(f => f.type.toUpperCase()).join(', ')}`,
      rawValue: missingAuth.map(f => f.type).join(', ')
    })
  }
  
  const hiddenRecipients = headers['bcc'] || ''
  if (hiddenRecipients) {
    indicators.push({
      type: 'hidden_recipients',
      severity: 'low',
      description: 'BCC recipients present - some recipients hidden from view'
    })
  }
  
  const xOriginatingIp = headers['x-originating-ip'] || headers['x-sender-ip'] || ''
  if (xOriginatingIp) {
    const suspiciousCountries = ['RU', 'CN', 'KP', 'IR', 'NG', 'GH']
    for (const country of suspiciousCountries) {
      if (xOriginatingIp.includes(country)) {
        indicators.push({
          type: 'suspicious_received',
          severity: 'low',
          description: `Email originated from suspicious region: ${country}`
        })
        break
      }
    }
  }
  
  return indicators
}

export function extractEmailIocs(emailContent: string): {
  addresses: string[]
  domains: string[]
  urls: string[]
  ips: string[]
} {
  const addresses: string[] = []
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
  const foundEmails = emailContent.match(emailRegex) || []
  addresses.push(...foundEmails)
  
  const domains = [...new Set(foundEmails.map(e => e.split('@')[1]))]
  
  const urlRegex = /(https?:\/\/[^\s<>"]+)/gi
  const foundUrls = emailContent.match(urlRegex) || []
  const urls = [...new Set(foundUrls)]
  
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b(?:\/\d{1,2})?(?!\d*['"])/g
  const foundIps = emailContent.match(ipRegex) || []
  const ips = [...new Set(foundIps.filter(ip => {
    const parts = ip.split('.')
    return parts.every(p => parseInt(p) <= 255)
  }))]
  
  return { addresses, domains, urls, ips }
}

export function calculateEmailRiskScore(
  parsed: ParsedEmail,
  iocs: ReturnType<typeof extractEmailIocs>
): { score: number; level: 'critical' | 'high' | 'medium' | 'low' | 'safe' } {
  let score = 0
  
  const highSeverity = parsed.analysis.suspiciousIndicators.filter(i => i.severity === 'high')
  const mediumSeverity = parsed.analysis.suspiciousIndicators.filter(i => i.severity === 'medium')
  const lowSeverity = parsed.analysis.suspiciousIndicators.filter(i => i.severity === 'low')
  
  score += highSeverity.length * 25
  score += mediumSeverity.length * 10
  score += lowSeverity.length * 3
  
  const failedAuth = parsed.analysis.authResults.filter(a => a.severity === 'fail')
  score += failedAuth.length * 20
  
  const failedFlags = parsed.analysis.securityFlags.filter(f => f.status === 'fail')
  score += failedFlags.length * 15
  
  if (parsed.analysis.fromAnalysis.disposableProvider) score += 15
  if (parsed.analysis.fromAnalysis.freeProvider) score += 5
  
  if (parsed.analysis.dateAnalysis.anomaly === 'future_date') score += 15
  if (parsed.analysis.dateAnalysis.anomaly === 'distant_past') score += 10
  
  if (iocs.urls.length > 0) score += 5
  if (iocs.ips.length > 0) score += 5
  
  score = Math.min(score, 100)
  
  let level: 'critical' | 'high' | 'medium' | 'low' | 'safe' = 'safe'
  if (score >= 80) level = 'critical'
  else if (score >= 60) level = 'high'
  else if (score >= 40) level = 'medium'
  else if (score >= 20) level = 'low'
  
  return { score, level }
}
