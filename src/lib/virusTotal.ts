const VIRUSTOTAL_API_KEY = 'REDACTED_VIRUSTOTAL_API_KEY'

export interface VirusTotalResult {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  last_analysis_date: string
  ratio: string
  vendor_results: Record<string, {
    category: string
    result: string
    method: string
    engine_name: string
  }>
}

export async function checkUrl(url: string): Promise<VirusTotalResult | null> {
  try {
    // First, get the URL ID (hash of the URL)
    const urlId = await getUrlId(url)
    if (!urlId) return null

    // Fetch the report
    const response = await fetch(`https://www.virustotal.com/api/v4/urls/${urlId}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
      },
    })

    if (!response.ok) {
      console.error('VirusTotal API error:', response.status)
      return null
    }

    const data = await response.json()
    
    const attributes = data.data?.attributes
    if (!attributes) return null

    const lastAnalysisStats = attributes.last_analysis_stats || {}
    
    return {
      malicious: lastAnalysisStats.malicious || 0,
      suspicious: lastAnalysisStats.suspicious || 0,
      harmless: lastAnalysisStats.harmless || 0,
      undetected: lastAnalysisStats.undetected || 0,
      last_analysis_date: attributes.last_analysis_date || '',
      ratio: `${(lastAnalysisStats.malicious || 0) + (lastAnalysisStats.suspicious || 0)}/${Object.values(lastAnalysisStats).reduce((a: number, b: unknown) => a + (typeof b === 'number' ? b : 0), 0)}`,
      vendor_results: attributes.last_analysis_results || {}
    }
  } catch (error) {
    console.error('VirusTotal check failed:', error)
    return null
  }
}

async function getUrlId(url: string): Promise<string | null> {
  try {
    // Submit URL for analysis
    const response = await fetch('https://www.virustotal.com/api/v4/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    })

    if (!response.ok) return null

    const data = await response.json()
    return data.data?.id || null
  } catch (error) {
    console.error('URL submission failed:', error)
    return null
  }
}

export async function checkDomain(domain: string): Promise<VirusTotalResult | null> {
  try {
    // Calculate MD5 hash of domain for API
    const domainHash = await hashString(domain)
    
    const response = await fetch(`https://www.virustotal.com/api/v4/domains/${domainHash}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
      },
    })

    if (!response.ok) return null

    const data = await response.json()
    const attributes = data.data?.attributes

    if (!attributes) return null

    const lastAnalysisStats = attributes.last_analysis_stats || {}
    
    return {
      malicious: lastAnalysisStats.malicious || 0,
      suspicious: lastAnalysisStats.suspicious || 0,
      harmless: lastAnalysisStats.harmless || 0,
      undetected: lastAnalysisStats.undetected || 0,
      last_analysis_date: attributes.last_analysis_date || '',
      ratio: `${(lastAnalysisStats.malicious || 0) + (lastAnalysisStats.suspicious || 0)}/${Object.values(lastAnalysisStats).reduce((a: number, b: unknown) => a + (typeof b === 'number' ? b : 0), 0)}`,
      vendor_results: attributes.last_analysis_results || {}
    }
  } catch (error) {
    console.error('VirusTotal domain check failed:', error)
    return null
  }
}

async function hashString(str: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(str)
  const hashBuffer = await crypto.subtle.digest('MD5', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}