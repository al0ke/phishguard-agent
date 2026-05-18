export interface BrandMatch {
  brand: string
  original_domain: string
  suspected_domain: string
  risk_level: 'high' | 'medium' | 'low'
  techniques: string[]
  similarity_score: number
}

const KNOWN_BRANDS = [
  { name: 'Microsoft', patterns: ['microsoft', 'ms', 'microsft', 'micros0ft', 'micr0soft', 'microsoftoffice'] },
  { name: 'Google', patterns: ['google', 'g0ogle', 'googl', 'googIe', 'g00gle'] },
  { name: 'Apple', patterns: ['apple', 'app1e', 'appl3', 'aiple', '4pple'] },
  { name: 'Amazon', patterns: ['amazon', 'amaz0n', 'amazn', 'amazom', 'amaz0naws'] },
  { name: 'PayPal', patterns: ['paypal', 'paypa1', 'paypai', 'payp4l', 'paypaI'] },
  { name: 'Netflix', patterns: ['netflix', 'netf1ix', 'netf1ix', 'netfiix', 'nettflix'] },
  { name: 'Facebook', patterns: ['facebook', 'faceb00k', 'faceboook', 'facbook', 'facebok'] },
  { name: 'Instagram', patterns: ['instagram', 'instagran', '1nstagram', 'instagran', 'instagarm'] },
  { name: 'Twitter', patterns: ['twitter', 'tw1tter', 'twiter', 'twitt3r', 'twttr'] },
  { name: 'LinkedIn', patterns: ['linkedin', '1inkedin', 'linkdin', 'linkedln', 'Iinkedin'] },
  { name: 'Microsoft365', patterns: ['microsoft365', 'ms365', 'ms-365', 'm365', 'office365', 'o365'] },
  { name: 'Dropbox', patterns: ['dropbox', 'dr0pbox', 'dropb0x', 'dropboox', 'drpbox'] },
  { name: 'Salesforce', patterns: ['salesforce', 'sa1esforce', 'slesforce', 'salesforc', 'salsforce'] },
  { name: 'Adobe', patterns: ['adobe', '4dobe', 'ad0be', 'adobe', 'ad0b3'] },
  { name: 'Bank of America', patterns: ['bankofamerica', 'bankofamerlca', 'bofa', 'bankofamerlca'] },
  { name: 'Chase', patterns: ['chase', 'ch4se', 'chas3', 'chasse'] },
  { name: 'Coinbase', patterns: ['coinbase', 'coinbse', 'coinbass', 'coinbaes'] },
  { name: 'CoinDesk', patterns: ['coindesk', 'coindesk', 'coindeskk', 'coindesq'] },
]

export function detectBrandImpersonation(url: string, emailContent?: string): BrandMatch[] {
  const matches: BrandMatch[] = []
  
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '')
    const pathParts = hostname.split('.')
    
    // Check all possible domain combinations
    for (const brand of KNOWN_BRANDS) {
      for (const pattern of brand.patterns) {
        // Check if hostname contains the brand pattern
        if (hostname.includes(pattern) && !hostname.includes(brand.name.toLowerCase())) {
          // This is a potential lookalike
          const techniques: string[] = []
          
          // Character replacement detection
          if (pattern !== brand.name.toLowerCase()) {
            const original = brand.name.toLowerCase()
            const suspected = pattern
            let differences = 0
            let type = ''
            
            for (let i = 0; i < suspected.length; i++) {
              if (suspected[i] !== original[i]) {
                differences++
                if (/\d/.test(suspected[i])) type = 'numbers'
                else if (suspected[i] === '0') type = 'zero for o'
                else if (suspected[i] === '1' || suspected[i] === 'l') type = 'one for l'
                else if (suspected[i] === '3') type = 'three for e'
                else if (suspected[i] === 'i') type = 'i for j'
                else type = 'character swap'
              }
            }
            
            if (differences > 0) {
              techniques.push(`Character substitution (${type})`)
            }
          }
          
          // Hyphenation detection
          if (hostname.includes('-') && !hostname.includes(brand.name.toLowerCase())) {
            techniques.push('Hyphenation attack')
          }
          
          // Subdomain detection
          if (pathParts.length > 2 && hostname.startsWith(pattern)) {
            techniques.push('Subdomain abuse')
          }
          
          // TLD spoofing
          const suspiciousTLDs = ['xyz', 'top', 'club', 'online', 'site', 'website', 'work', 'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq']
          const tld = hostname.split('.').pop()
          if (tld && suspiciousTLDs.includes(tld) && !hostname.includes(brand.name.toLowerCase())) {
            techniques.push(`Suspicious TLD (.${tld})`)
          }
          
          if (techniques.length > 0) {
            matches.push({
              brand: brand.name,
              original_domain: `${brand.name.toLowerCase()}.com`,
              suspected_domain: hostname,
              risk_level: techniques.length >= 2 ? 'high' : techniques.length === 1 ? 'medium' : 'low',
              techniques,
              similarity_score: calculateSimilarity(brand.name.toLowerCase(), pattern)
            })
          }
        }
      }
    }
  } catch (error) {
    console.error('Brand detection error:', error)
  }
  
  return matches
}

function calculateSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2
  const shorter = str1.length > str2.length ? str2 : str1
  
  if (longer.length === 0) return 1.0
  
  const editDistance = levenshteinDistance(longer, shorter)
  return (longer.length - editDistance) / longer.length
}

function levenshteinDistance(str1: string, str2: string): number {
  const matrix: number[][] = []
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i]
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2[i - 1] === str1[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
      }
    }
  }
  
  return matrix[str2.length][str1.length]
}

export function extractUrls(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/gi
  const matches = text.match(urlRegex) || []
  
  // Also catch common URL patterns without protocol
  const domainRegex = /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9]+)+[^\s<>"{}|\\^`\[\]]*)/gi
  const domainMatches = text.match(domainRegex) || []
  
  return [...matches, ...domainMatches].filter((url, index, self) => 
    index === self.findIndex(u => u.toLowerCase() === url.toLowerCase())
  )
}

export function parseEmailForThreats(emailContent: string): {
  urls: string[]
  suspiciousKeywords: string[]
  senderAnalysis: string | null
} {
  const urls = extractUrls(emailContent)
  
  const suspiciousKeywords = [
    'urgent', 'verify', 'account', 'suspended', 'confirm identity',
    'click here', 'act now', 'immediate action', 'password',
    'social security', 'ssn', 'bank account', 'wire transfer',
    'cryptocurrency', 'bitcoin', 'gift card', 'update payment'
  ]
  
  const foundKeywords = suspiciousKeywords.filter(keyword => 
    emailContent.toLowerCase().includes(keyword.toLowerCase())
  )
  
  // Extract sender from common patterns
  const senderMatch = emailContent.match(/(?:from|sender)[:\s]+([^\s<>]+@[^\s<>]+)/i)
  
  return {
    urls,
    suspiciousKeywords: foundKeywords,
    senderAnalysis: senderMatch ? senderMatch[1] : null
  }
}