const VIRUSTOTAL_API_KEY='REDACTED_VIRUSTOTAL_API_KEY'

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
    // Submit URL for analysis using V3 API
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    })

    if (!submitResponse.ok) {
      console.error('VirusTotal submission error:', submitResponse.status)
      return null
    }

    const submitData = await submitResponse.json()
    const analysisId = submitData.data?.id
    
    if (!analysisId) {
      // URL was already in VT database - try to get the report directly
      const urlHash = await hashString(url)
      return await getUrlReport(urlHash)
    }
    
    // Poll for results (wait a moment for VT to process)
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    // Extract the analysis UUID from the ID
    const analysisUuid = analysisId.split('-')[0]
    
    const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
      },
    })

    if (!reportResponse.ok) {
      console.error('VirusTotal report error:', reportResponse.status)
      return null
    }

    const reportData = await reportResponse.json()
    const attributes = reportData.data?.attributes
    
    if (!attributes) return null

    const stats = attributes.stats || {}
    
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      last_analysis_date: attributes.date ? attributes.date.toString() : '',
      ratio: `${(stats.malicious || 0) + (stats.suspicious || 0)}/${Object.values(stats).reduce((a: number, b: unknown) => a + (typeof b === 'number' ? b : 0), 0)}`,
      vendor_results: attributes.results || {}
    }
  } catch (error) {
    console.error('VirusTotal check failed:', error)
    return null
  }
}

async function getUrlReport(urlHash: string): Promise<VirusTotalResult | null> {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlHash}`, {
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
    console.error('VirusTotal get report failed:', error)
    return null
  }
}

export async function checkDomain(domain: string): Promise<VirusTotalResult | null> {
  try {
    const domainHash = await hashString(domain)
    
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domainHash}`, {
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
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}