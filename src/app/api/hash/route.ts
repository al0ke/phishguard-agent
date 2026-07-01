import { NextRequest, NextResponse } from 'next/server'

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || ''
const VT_BASE = 'https://www.virustotal.com/api/v3'

type HashType = 'MD5' | 'SHA1' | 'SHA256' | null

interface VtEngineResult {
  category: string
  result: string
  method: string
  engine_name: string
}

function detectHashType(hash: string): HashType {
  const h = hash.trim().toLowerCase()
  if (/^[a-f0-9]{32}$/.test(h)) return 'MD5'
  if (/^[a-f0-9]{40}$/.test(h)) return 'SHA1'
  if (/^[a-f0-9]{64}$/.test(h)) return 'SHA256'
  return null
}

export async function POST(request: NextRequest) {
  try {
    const { hash } = await request.json()

    if (!hash || typeof hash !== 'string') {
      return NextResponse.json({ error: 'Hash required' }, { status: 400 })
    }

    const normalized = hash.trim()
    const hashType = detectHashType(normalized)

    if (!hashType) {
      return NextResponse.json({
        error: 'Invalid hash format',
        supported: ['MD5 (32 hex chars)', 'SHA1 (40 hex chars)', 'SHA256 (64 hex chars)'],
      }, { status: 400 })
    }

    const vtRes = await fetch(`${VT_BASE}/files/${normalized}`, {
      headers: { 'x-apikey': VT_API_KEY },
    })

    if (vtRes.status === 404) {
      return NextResponse.json({
        hash: normalized,
        hashType,
        status: 'unknown',
        message: 'Hash not found in VirusTotal database',
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        harmless: 0,
        last_analysis_date: null,
        ratio: '0/unknown',
      })
    }

    if (!vtRes.ok) {
      if (vtRes.status === 401) {
        return NextResponse.json({
          hash: normalized,
          hashType,
          status: 'error',
          message: 'VirusTotal API key invalid or expired. Set VIRUSTOTAL_API_KEY env var with a valid key.',
          malicious: 0, suspicious: 0, undetected: 0, harmless: 0,
          last_analysis_date: null, ratio: '0/0',
          names: [],
        })
      }
      return NextResponse.json({ error: `VirusTotal API error ${vtRes.status}` }, { status: 502 })
    }

    const data = await vtRes.json()
    const attrs = data.data?.attributes
    const stats = attrs?.last_analysis_stats || {}

    return NextResponse.json({
      hash: normalized,
      hashType,
      status: (stats.malicious || 0) > 0 ? 'malicious' : (stats.suspicious || 0) > 0 ? 'suspicious' : 'clean',
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      last_analysis_date: attrs?.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      ratio: (() => {
        const vals = Object.values(stats) as number[]
        const total = vals.reduce((a, b) => a + b, 0)
        return `${(stats.malicious || 0) + (stats.suspicious || 0)}/${total}`
      })(),
      names: attrs?.last_analysis_results ? Object.entries(attrs.last_analysis_results as Record<string, VtEngineResult>)
        .filter(([, v]) => v.category !== 'harmless' && v.category !== 'undetected')
        .map(([engine, v]) => ({ engine, result: v.result, category: v.category }))
        .slice(0, 20)
        : [],
    })
  } catch (err) {
    console.error('Hash route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}
