export interface URLhausResult {
  url_status: string
  threat_type: string | null
  threat_score: number | null
  firstseen: string
  lastseen: string | null
 haus_score: number | null
  tags: string[]
  reference: string | null
  payload: {
    origin: string
    ip_address: string | null
    ip_country: string | null
    hostname: string | null
    port: number | null
    uri: string | null
  }
}

export async function checkURLhaus(url: string): Promise<URLhausResult | null> {
  try {
    const encodedUrl = encodeURIComponent(url)
    const response = await fetch(`https://urlhaus-api.abuse.ch/v1/lookup/url/${encodedUrl}/`, {
      headers: {
        'Accept': 'application/json',
      },
    })

    if (!response.ok) {
      console.error('URLhaus API error:', response.status)
      return null
    }

    const data = await response.json()
    
    if (data.query_status === 'no_results') {
      return null
    }

    return {
      url_status: data.url_status || 'unknown',
      threat_type: data.threat_type || null,
      threat_score: data.threat_score || null,
      firstseen: data.firstseen || '',
      lastseen: data.lastseen || null,
      haus_score: data.haus_score || null,
      tags: data.tags || [],
      reference: data.reference || null,
      payload: {
        origin: data.payload?.origin || '',
        ip_address: data.payload?.ip_address || null,
        ip_country: data.payload?.ip_country || null,
        hostname: data.payload?.hostname || null,
        port: data.payload?.port || null,
        uri: data.payload?.uri || null
      }
    }
  } catch (error) {
    console.error('URLhaus check failed:', error)
    return null
  }
}

export async function checkURLhausDomain(domain: string): Promise<any | null> {
  try {
    const response = await fetch(`https://urlhaus-api.abuse.ch/v1/lookup/host/${domain}/`, {
      headers: {
        'Accept': 'application/json',
      },
    })

    if (!response.ok) return null

    const data = await response.json()
    
    if (data.query_status === 'no_results') return null

    return data
  } catch (error) {
    console.error('URLhaus domain check failed:', error)
    return null
  }
}