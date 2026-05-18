import { NextRequest, NextResponse } from 'next/server'
import { checkUrl } from '../../../lib/virusTotal'
import { checkURLhaus } from '../../../lib/urlhaus'
import { detectBrandImpersonation, extractUrls } from '../../../lib/brandDetection'

interface AnalysisResult {
  timestamp: string
  input: string
  inputType: 'url' | 'email' | 'domain'
  overallVerdict: 'malicious' | 'suspicious' | 'safe' | 'unknown'
  riskScore: number
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
  
  urlsAnalyzed: string[]
  virusTotal?: {
    status: string
    malicious: number
    suspicious: number
    ratio: string
    lastAnalysisDate: string
  }
  urlhaus?: {
    status: string
    threatType: string | null
    firstSeen: string
    country?: string
    hausScore?: number
  }
  brandImpersonation?: {
    brand: string
    originalDomain: string
    suspectedDomain: string
    riskLevel: string
    techniques: string[]
  }[]
  
  iocs: {
    ips: string[]
    domains: string[]
    urls: string[]
    hashes: string[]
  }
  
  aiVerdict: {
    summary: string
    recommendations: string[]
    confidence: number
  }
}

function extractIOCs(text: string) {
  const iocs = {
    ips: [] as string[],
    domains: [] as string[],
    urls: [] as string[],
    hashes: [] as string[]
  }
  
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b(?:\/\d{1,2})?/g
  const ipMatches = text.match(ipRegex) || []
  iocs.ips = [...new Set(ipMatches.filter(ip => {
    const parts = ip.split('.')
    return parts.every(p => parseInt(p) <= 255)
  }))]
  
  iocs.urls = extractUrls(text)
  
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/gi
  const domainMatches = text.match(domainRegex) || []
  iocs.domains = [...new Set(domainMatches)]
  
  const hashRegex = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g
  const hashMatches = text.match(hashRegex) || []
  iocs.hashes = [...new Set(hashMatches)]
  
  return iocs
}

function calculateRiskScore(
  virusTotal: any,
  urlhaus: any,
  brandMatches: any[]
): { score: number; level: string } {
  let score = 0
  
  if (virusTotal) {
    if (virusTotal.malicious > 5) score += 35
    else if (virusTotal.malicious > 2) score += 25
    else if (virusTotal.malicious > 0) score += 15
    else if (virusTotal.suspicious > 0) score += 10
  }
  
  if (urlhaus) {
    if (urlhaus.status === 'malicious') score += 30
    else if (urlhaus.status === 'suspicious') score += 20
    else if (urlhaus.threatType) score += 15
  }
  
  if (brandMatches.length > 0) {
    const maxRisk = brandMatches.reduce((max: number, match: any) => {
      if (match.risk_level === 'high') return 20
      if (match.risk_level === 'medium') return 15
      return 5
    }, 0)
    score += maxRisk
  }
  
  score = Math.min(score, 100)
  
  let level = 'safe'
  if (score >= 80) level = 'critical'
  else if (score >= 60) level = 'high'
  else if (score >= 40) level = 'medium'
  else if (score >= 20) level = 'low'
  
  return { score, level }
}

function generateVerdict(result: AnalysisResult): AnalysisResult['aiVerdict'] {
  const recommendations: string[] = []
  let summary = ''
  const confidence = 0.85
  
  if (result.overallVerdict === 'malicious') {
    summary = `THREAT DETECTED: This ${result.inputType} is confirmed malicious with a risk score of ${result.riskScore}/100. `
    
    if (result.virusTotal && result.virusTotal.malicious > 0) {
      summary += `VirusTotal reports ${result.virusTotal.malicious} security vendors flagging this as malicious. `
    }
    
    if (result.urlhaus && result.urlhaus.status === 'malicious') {
      summary += `Listed in URLhaus as ${result.urlhaus.threatType || 'malicious'}. `
    }
    
    if (result.brandImpersonation && result.brandImpersonation.length > 0) {
      const brands = result.brandImpersonation.map((b: any) => b.brand).join(', ')
      summary += `Brand impersonation detected: ${brands}. `
    }
    
    recommendations.push('DO NOT click or visit this URL')
    recommendations.push('Block this domain at the network level')
    recommendations.push('Report to your security team immediately')
    recommendations.push('If credentials were entered, reset them immediately')
    recommendations.push('Scan endpoints for malware')
    
    if (result.iocs.ips.length > 0) {
      recommendations.push(`Block IP addresses: ${result.iocs.ips.join(', ')}`)
    }
    
  } else if (result.overallVerdict === 'suspicious') {
    summary = `SUSPICIOUS ACTIVITY: This ${result.inputType} shows concerning indicators with a risk score of ${result.riskScore}/100. `
    
    if (result.brandImpersonation && result.brandImpersonation.length > 0) {
      const brands = result.brandImpersonation.map((b: any) => b.brand).join(', ')
      summary += `Potential ${brands} brand impersonation detected. `
    }
    
    if (result.virusTotal && result.virusTotal.suspicious > 0) {
      summary += `${result.virusTotal.suspicious} vendors flagged this as suspicious. `
    }
    
    recommendations.push('Exercise extreme caution with this content')
    recommendations.push('Verify the sender through alternative channels')
    recommendations.push('Do not enter credentials or personal information')
    recommendations.push('Report to your security team for review')
    recommendations.push('If possible, analyze in a sandboxed environment')
    
  } else if (result.overallVerdict === 'unknown') {
    summary = `UNCLEAR RISK: This ${result.inputType} has a low risk score of ${result.riskScore}/100 but lacks comprehensive threat intelligence. `
    recommendations.push('Continue with caution')
    recommendations.push('Monitor for additional indicators')
    recommendations.push('Consider additional threat intelligence checks')
    
  } else {
    summary = `CLEAN: No malicious indicators detected for this ${result.inputType}. Risk score: ${result.riskScore}/100. `
    recommendations.push('Content appears safe based on available threat intelligence')
    recommendations.push('Continue standard security awareness practices')
  }
  
  return { summary: summary.trim(), recommendations, confidence }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { input } = body
    
    if (!input || typeof input !== 'string') {
      return NextResponse.json(
        { error: 'Input is required' },
        { status: 400 }
      )
    }
    
    const result: AnalysisResult = {
      timestamp: new Date().toISOString(),
      input,
      inputType: 'url',
      overallVerdict: 'unknown',
      riskScore: 0,
      threatLevel: 'safe',
      urlsAnalyzed: [],
      iocs: { ips: [], domains: [], urls: [], hashes: [] },
      aiVerdict: {
        summary: '',
        recommendations: [],
        confidence: 0
      }
    }
    
    const inputTrimmed = input.trim()
    if (inputTrimmed.includes('@') && (inputTrimmed.includes('Subject:') || inputTrimmed.includes('Dear'))) {
      result.inputType = 'email'
    } else if (inputTrimmed.startsWith('http')) {
      result.inputType = 'url'
    } else {
      result.inputType = 'domain'
    }
    
    const extractedUrls = extractUrls(inputTrimmed)
    result.urlsAnalyzed = extractedUrls.length > 0 ? extractedUrls : [inputTrimmed]
    
    const primaryUrl = result.urlsAnalyzed[0]
    
    const [virusTotalResult, urlhausResult, brandMatches] = await Promise.all([
      primaryUrl.startsWith('http') ? checkUrl(primaryUrl) : Promise.resolve(null),
      primaryUrl.startsWith('http') ? checkURLhaus(primaryUrl) : Promise.resolve(null),
      Promise.resolve(detectBrandImpersonation(primaryUrl, inputTrimmed))
    ])
    
    if (virusTotalResult) {
      result.virusTotal = {
        status: virusTotalResult.malicious > 0 ? 'malicious' : virusTotalResult.suspicious > 0 ? 'suspicious' : 'clean',
        malicious: virusTotalResult.malicious,
        suspicious: virusTotalResult.suspicious,
        ratio: virusTotalResult.ratio,
        lastAnalysisDate: virusTotalResult.last_analysis_date
      }
    }
    
    if (urlhausResult) {
      result.urlhaus = {
        status: urlhausResult.url_status,
        threatType: urlhausResult.threat_type,
        firstSeen: urlhausResult.firstseen,
        country: urlhausResult.payload?.ip_country || undefined,
        hausScore: urlhausResult.haus_score || undefined
      }
    }
    
    if (brandMatches.length > 0) {
      result.brandImpersonation = brandMatches.map((m: any) => ({
        brand: m.brand,
        originalDomain: m.original_domain,
        suspectedDomain: m.suspected_domain,
        riskLevel: m.risk_level,
        techniques: m.techniques
      }))
    }
    
    result.iocs = extractIOCs(inputTrimmed)
    
    const riskResult = calculateRiskScore(result.virusTotal, result.urlhaus, brandMatches)
    result.riskScore = riskResult.score
    result.threatLevel = riskResult.level as any
    
    if (result.riskScore >= 60 || (result.virusTotal?.malicious || 0) > 5) {
      result.overallVerdict = 'malicious'
    } else if (result.riskScore >= 30 || (result.virusTotal?.suspicious || 0) > 0 || brandMatches.length > 0) {
      result.overallVerdict = 'suspicious'
    } else if (result.riskScore > 0) {
      result.overallVerdict = 'unknown'
    } else {
      result.overallVerdict = 'safe'
    }
    
    result.aiVerdict = generateVerdict(result)
    
    return NextResponse.json(result)
  } catch (error) {
    console.error('Analysis error:', error)
    return NextResponse.json(
      { error: 'Analysis failed' },
      { status: 500 }
    )
  }
}