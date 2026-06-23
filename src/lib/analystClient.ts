import { getMitreTags } from './mitre'

export function saveToHistory(
  type: string,
  target: string,
  riskScore?: number,
  threatLevel?: string
) {
  if (typeof window === 'undefined') return
  const item = {
    type,
    target,
    timestamp: new Date().toISOString(),
    riskScore,
    threatLevel,
  }
  const raw = localStorage.getItem('threatAnalyzer_history')
  const history = raw ? JSON.parse(raw) : []
  history.unshift(item)
  localStorage.setItem('threatAnalyzer_history', JSON.stringify(history.slice(0, 50)))
}

export async function logAudit(params: {
  tool: string
  target: string
  riskScore?: number | null
  threatLevel?: string
  findings?: string[]
  user?: string
}) {
  const threatLevel = params.threatLevel || 'unknown'
  const mitreTags = getMitreTags(threatLevel, params.tool, params.findings || [])

  try {
    await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'add',
        entry: {
          tool: params.tool,
          target: params.target,
          riskScore: params.riskScore ?? null,
          threatLevel,
          mitreTags: mitreTags.map(t => t.id),
          user: params.user || 'analyst',
        },
      }),
    })
  } catch {
    /* non-fatal */
  }

  saveToHistory(params.tool, params.target, params.riskScore ?? undefined, threatLevel)
  return mitreTags
}

export function saveLastResult(data: Record<string, unknown>) {
  if (typeof window === 'undefined') return
  localStorage.setItem('threatAnalyzer_lastResult', JSON.stringify(data))
}

export function saveTriageSession(data: Record<string, unknown>) {
  if (typeof window === 'undefined') return
  localStorage.setItem('threatAnalyzer_triageSession', JSON.stringify(data))
}
