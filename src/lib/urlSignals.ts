export interface PunycodeCheck {
  suspicious: boolean
  hostname: string
  asciiHostname?: string
  reason?: string
}

export function detectPunycode(input: string): PunycodeCheck | null {
  try {
    const url = input.startsWith('http') ? input : `https://${input}`
    const hostname = new URL(url).hostname
    const hasPunycode = hostname.includes('xn--')
    const nonAscii = /[^\x00-\x7F]/.test(hostname)

    if (!hasPunycode && !nonAscii) {
      return { suspicious: false, hostname }
    }

    let asciiHostname = hostname
    try {
      asciiHostname = hostname.split('.').map(part => {
        if (part.startsWith('xn--')) {
          return part.replace(/^xn--/, '')
        }
        return part
      }).join('.')
    } catch {
      /* keep original */
    }

    return {
      suspicious: true,
      hostname,
      asciiHostname,
      reason: hasPunycode
        ? 'Punycode domain detected — possible homograph impersonation'
        : 'Non-ASCII characters in hostname — possible lookalike domain',
    }
  } catch {
    return null
  }
}

export async function getDomainAge(domain: string): Promise<{
  ageDays: number | null
  created: string | null
  registrar: string | null
}> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'User-Agent': 'ThreatAnalyzer/2.1' },
    })
    if (!res.ok) return { ageDays: null, created: null, registrar: null }
    const data = await res.json()
    const events = data.events || []
    const regEvent = events.find((e: { eventAction?: string }) => e.eventAction === 'registration')
    const created = regEvent?.eventDate || null
    let ageDays: number | null = null
    if (created) {
      ageDays = Math.floor((Date.now() - new Date(created).getTime()) / (1000 * 60 * 60 * 24))
    }
    const registrar = data.entities?.find((e: { roles?: string[] }) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.[1]?.[3] || null
    return { ageDays, created, registrar }
  } catch {
    return { ageDays: null, created: null, registrar: null }
  }
}

export function extractHostname(input: string): string | null {
  try {
    if (input.startsWith('http')) return new URL(input).hostname
    if (input.includes('.') && !input.includes(' ')) return input.replace(/^www\./, '').split('/')[0]
    return null
  } catch {
    return null
  }
}
