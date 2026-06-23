import { NextRequest, NextResponse } from 'next/server'
import { parseEmailHeaders, extractEmailIocs, calculateEmailRiskScore } from '../../../lib/emailHeaders'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { emailContent } = body
    
    if (!emailContent || typeof emailContent !== 'string') {
      return NextResponse.json(
        { error: 'Email content is required' },
        { status: 400 }
      )
    }
    
    const parsed = parseEmailHeaders(emailContent)
    const iocs = extractEmailIocs(emailContent)
    const riskResult = calculateEmailRiskScore(parsed, iocs)
    
    return NextResponse.json({
      parsed,
      iocs,
      riskScore: riskResult.score,
      riskLevel: riskResult.level,
      threatIndicators: parsed.analysis.suspiciousIndicators,
      securityFlags: parsed.analysis.securityFlags,
      authResults: parsed.analysis.authResults,
      routingPath: parsed.analysis.routingPath,
      fromAnalysis: parsed.analysis.fromAnalysis,
      replyToAnalysis: parsed.analysis.replyToAnalysis,
      dateAnalysis: parsed.analysis.dateAnalysis
    })
  } catch (error) {
    console.error('Email header analysis error:', error)
    return NextResponse.json(
      { error: 'Failed to analyze email headers' },
      { status: 500 }
    )
  }
}
