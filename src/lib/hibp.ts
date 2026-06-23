export interface HibpBreach {
  Name: string
  Title: string
  Domain: string
  BreachDate: string
  AddedDate: string
  ModifiedDate: string
  PwnCount: number
  Description: string
  LogoPath: string
  DataClasses: string[]
  IsVerified: boolean
  IsFabricated: boolean
  IsSensitive: boolean
  IsRetired: boolean
  IsSpamList: boolean
  IsMalware: boolean
  IsSubscriptionFree: boolean
}

export interface HibpPaste {
  Id: string
  Title: string
  EmailCount: number
  PasswordCount: number
  Databases: string[]
  Source: string
  Date: string
}

export interface HibpCheckResult {
  email: string
  breaches: HibpBreach[]
  pastes: HibpPaste[]
  totalBreaches: number
  totalPastes: number
  breachStats: {
    mostCommonClass: string | null
    latestBreach: string | null
    highestPwnCount: number
    verifiedBreaches: number
  }
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
  recommendations: string[]
}

const HIBP_API_BASE = 'https://haveibeenpwned.com/api/v3'

export async function checkHibpBreaches(email: string): Promise<HibpCheckResult | null> {
  try {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'PhishGuard-Email-Security-Tool'
    }
    
    const response = await fetch(`${HIBP_API_BASE}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers
    })
    
    const breaches: HibpBreach[] = []
    
    if (response.ok) {
      const data = await response.json()
      if (Array.isArray(data)) {
        breaches.push(...data)
      } else if (data) {
        breaches.push(data)
      }
    } else if (response.status !== 404) {
      console.error('HIBP API error:', response.status, response.statusText)
    }
    
    const pasteResponse = await fetch(`${HIBP_API_BASE}/pasteaccount/${encodeURIComponent(email)}`, {
      headers
    })
    
    const pastes: HibpPaste[] = []
    if (pasteResponse.ok) {
      const pasteData = await pasteResponse.json()
      if (Array.isArray(pasteData)) {
        pastes.push(...pasteData)
      } else if (pasteData) {
        pastes.push(pasteData)
      }
    }
    
    const result = buildHibpResult(email, breaches, pastes)
    return result
  } catch (error) {
    console.error('HIBP check failed:', error)
    return null
  }
}

export async function checkHibpPassword(password: string): Promise<{ found: boolean; count: number } | null> {
  try {
    const hash = await hashSha1(password.toUpperCase())
    const prefix = hash.substring(0, 5)
    const suffix = hash.substring(5)
    
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        'User-Agent': 'PhishGuard-Email-Security-Tool'
      }
    })
    
    if (!response.ok) return null
    
    const data = await response.text()
    const lines = data.split('\n')
    
    for (const line of lines) {
      const [hashSuffix, count] = line.split(':')
      if (hashSuffix.trim().toUpperCase() === suffix) {
        return { found: true, count: parseInt(count.trim(), 10) }
      }
    }
    
    return { found: false, count: 0 }
  } catch (error) {
    console.error('HIBP password check failed:', error)
    return null
  }
}

async function hashSha1(str: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(str)
  const hashBuffer = await crypto.subtle.digest('SHA-1', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

function buildHibpResult(email: string, breaches: HibpBreach[], pastes: HibpPaste[]): HibpCheckResult {
  const totalBreaches = breaches.length
  const totalPastes = pastes.length
  
  const dataClassCounts: Record<string, number> = {}
  let latestBreach: string | null = null
  let highestPwnCount = 0
  let verifiedBreaches = 0
  
  for (const breach of breaches) {
    for (const dataClass of breach.DataClasses) {
      dataClassCounts[dataClass] = (dataClassCounts[dataClass] || 0) + 1
    }
    
    if (!latestBreach || new Date(breach.BreachDate) > new Date(latestBreach)) {
      latestBreach = breach.BreachDate
    }
    
    if (breach.PwnCount > highestPwnCount) {
      highestPwnCount = breach.PwnCount
    }
    
    if (breach.IsVerified) verifiedBreaches++
  }
  
  const mostCommonClass = Object.entries(dataClassCounts)
    .sort((a, b) => b[1] - a[1])[0]?.[0] || null
  
  const recommendations: string[] = []
  let riskLevel: HibpCheckResult['riskLevel'] = 'safe'
  
  if (totalBreaches >= 5) {
    riskLevel = 'critical'
    recommendations.push('URGENT: This email appears in 5+ data breaches')
    recommendations.push('Assume all associated accounts are compromised')
    recommendations.push('Use a password manager to generate unique passwords')
  } else if (totalBreaches >= 3) {
    riskLevel = 'high'
    recommendations.push('This email has been exposed in multiple breaches')
    recommendations.push('Change passwords for all potentially affected accounts')
  } else if (totalBreaches >= 1) {
    riskLevel = 'medium'
    recommendations.push('This email was found in at least one data breach')
    recommendations.push('Review the specific breach details and take appropriate action')
  }
  
  if (totalPastes >= 3) {
    if (riskLevel !== 'critical') riskLevel = 'high'
    recommendations.push('This email appears in multiple paste databases')
    recommendations.push('Be aware that your data may be actively traded/shared')
  }
  
  if (breaches.some(b => b.DataClasses.includes('Passwords') || b.DataClasses.includes('Password'))) {
    if (riskLevel !== 'critical') riskLevel = 'critical'
    recommendations.push('Passwords were exposed in a breach - CHANGE PASSWORDS IMMEDIATELY')
  }
  
  if (breaches.some(b => b.DataClasses.includes('Social security numbers') || b.DataClasses.includes('National ID numbers'))) {
    if (riskLevel !== 'critical') riskLevel = 'critical'
    recommendations.push('Sensitive identification numbers were exposed - monitor for identity theft')
  }
  
  if (breaches.some(b => b.DataClasses.includes('Credit cards') || b.DataClasses.includes('Bank account numbers'))) {
    if (riskLevel !== 'critical') riskLevel = 'critical'
    recommendations.push('Financial information was exposed - monitor accounts and consider fraud alerts')
  }
  
  if (riskLevel === 'safe') {
    recommendations.push('No breaches found for this email address')
    recommendations.push('Continue using strong, unique passwords and enable 2FA')
  }
  
  recommendations.push('Enable notifications at haveibeenpwned.com for future breaches')
  
  return {
    email,
    breaches,
    pastes,
    totalBreaches,
    totalPastes,
    breachStats: {
      mostCommonClass,
      latestBreach,
      highestPwnCount,
      verifiedBreaches
    },
    riskLevel,
    recommendations
  }
}

export function getBreachSeverity(breach: HibpBreach): 'critical' | 'high' | 'medium' | 'low' {
  const criticalData = ['Passwords', 'Social security numbers', 'National ID numbers', 'Bank account numbers', 'Credit cards']
  const hasCritical = breach.DataClasses.some(d => criticalData.includes(d))
  if (hasCritical) return 'critical'
  
  const sensitiveData = ['Phone numbers', 'Physical addresses', 'Dates of birth', 'Government ID numbers']
  const hasSensitive = breach.DataClasses.some(d => sensitiveData.includes(d))
  if (hasSensitive) return 'medium'
  
  if (breach.IsSpamList || breach.IsMalware) return 'high'
  
  return 'low'
}
