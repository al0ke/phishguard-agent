'use client'

import { useState, useRef, useCallback } from 'react'

interface ThreatIndicator {
  type: string
  severity: string
  description: string
}

interface QrResult {
  data: string
  format: string
  decoded: {
    type: string
    value: string
    isSuspicious: boolean
    threatIndicators: ThreatIndicator[]
  }
}

export default function QrCodeAnalyzer() {
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<QrResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setSelectedFile(file)
    setError(null)
    setResult(null)

    const reader = new FileReader()
    reader.onload = (event) => {
      setPreviewUrl(event.target?.result as string)
    }
    reader.readAsDataURL(file)
  }, [])

  const handleAnalyze = async () => {
    if (!selectedFile) return

    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const img = new Image()
      const url = URL.createObjectURL(selectedFile)

      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve()
        img.onerror = () => reject(new Error('Failed to load image'))
        img.src = url
      })

      const canvas = document.createElement('canvas')
      canvas.width = img.width
      canvas.height = img.height
      const ctx = canvas.getContext('2d')
      
      if (!ctx) {
        throw new Error('Failed to get canvas context')
      }

      ctx.drawImage(img, 0, 0)
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)

      const response = await fetch('/api/qrcode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageData: Array.from(imageData.data),
          width: canvas.width,
          height: canvas.height
        }),
      })

      URL.revokeObjectURL(url)

      if (!response.ok) {
        const errData = await response.json()
        throw new Error(errData.error || 'QR analysis failed')
      }

      const data = await response.json()
      
      const analyzedResult = analyzeDecodedData(data.data)
      setResult({
        ...data,
        decoded: analyzedResult
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze QR code')
    } finally {
      setIsLoading(false)
    }
  }

  const analyzeDecodedData = (data: string) => {
    const threatIndicators: ThreatIndicator[] = []
    let type = 'text'
    let value = data
    let isSuspicious = false

    const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'buzz', 'account', 'update', 'secure', 'verify', 'login', 'signin', 'bank', 'alert']
    const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
    const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'account', 'update', 'secure', 'banking', 'password', 'credential']

    if (data.startsWith('http://') || data.startsWith('https://')) {
      type = 'url'
      value = data
      
      try {
        const url = new URL(data)
        const hostname = url.hostname.toLowerCase()

        for (const keyword of SUSPICIOUS_KEYWORDS) {
          if (hostname.includes(keyword)) {
            threatIndicators.push({
              type: 'suspicious_keyword',
              severity: 'medium',
              description: `URL contains suspicious keyword: "${keyword}"`
            })
            isSuspicious = true
          }
        }

        if (SHORTENER_DOMAINS.some(d => hostname.includes(d))) {
          threatIndicators.push({
            type: 'shortened_url',
            severity: 'medium',
            description: 'URL uses a URL shortening service'
          })
          isSuspicious = true
        }

        const tld = hostname.split('.').pop()?.toLowerCase()
        if (tld && SUSPICIOUS_TLDS.includes(tld)) {
          threatIndicators.push({
            type: 'suspicious_tld',
            severity: 'low',
            description: `URL uses a high-risk TLD (.${tld})`
          })
          isSuspicious = true
        }

        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
        if (ipPattern.test(hostname)) {
          threatIndicators.push({
            type: 'ip_address',
            severity: 'high',
            description: 'URL uses raw IP address instead of domain'
          })
          isSuspicious = true
        }

        const brands = ['apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'paypal', 'bank']
        for (const brand of brands) {
          if (hostname.includes(brand) && !hostname.includes(`${brand}.com`) && !hostname.includes(`${brand}.`)) {
            threatIndicators.push({
              type: 'suspicious_domain',
              severity: 'high',
              description: `Possible ${brand} brand impersonation`
            })
            isSuspicious = true
            break
          }
        }
      } catch (e) {
        threatIndicators.push({
          type: 'suspicious_url',
          severity: 'low',
          description: 'Unable to parse URL structure'
        })
      }
    } else if (data.startsWith('mailto:')) {
      type = 'email'
      value = data.replace('mailto:', '')
    } else if (data.startsWith('tel:')) {
      type = 'phone'
      value = data.replace('tel:', '')
    } else if (data.startsWith('sms:') || data.startsWith('smsto:')) {
      type = 'sms'
      value = data.split('?')[0].replace(/^smsto:|^sms:/, '')
    } else if (data.startsWith('WIFI:')) {
      type = 'wifi'
      value = data
      
      if (!data.includes('T:WPA') && !data.includes('T:WEP')) {
        threatIndicators.push({
          type: 'suspicious_domain',
          severity: 'high',
          description: 'Open WiFi network - data can be intercepted'
        })
        isSuspicious = true
      }
    } else if (data.startsWith('BEGIN:VCARD')) {
      type = 'vcard'
      value = data
    } else if (data.startsWith('BEGIN:VEVENT')) {
      type = 'calendar'
      value = data
    }

    return { type, value, isSuspicious, threatIndicators }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return '#ff3366'
      case 'medium': return '#ffcc00'
      case 'low': return '#00ccff'
      default: return '#00ff88'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'url': return '🔗'
      case 'email': return '📧'
      case 'phone': return '📞'
      case 'sms': return '💬'
      case 'wifi': return '📶'
      case 'vcard': return '📇'
      case 'calendar': return '📅'
      default: return '📝'
    }
  }

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <div className="relative">
        <div className="absolute -inset-0.5 bg-gradient-to-r from-[#00ff88] via-[#ffcc00] to-[#00ff88] rounded-xl blur opacity-30" />
        <div className="relative bg-[#111119] rounded-xl p-6 border border-[#1a1a2e]">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center">
              <span className="text-xl">📱</span>
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">QR Code Analysis</h3>
              <p className="text-sm text-gray-400">Upload a QR code image to analyze its content</p>
            </div>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleFileSelect}
            className="hidden"
          />

          {previewUrl ? (
            <div className="space-y-4">
              <div className="relative bg-[#0a0a0f] rounded-lg p-4 flex items-center justify-center">
                <img
                  src={previewUrl}
                  alt="QR Code Preview"
                  className="max-h-64 max-w-full rounded-lg"
                />
                <button
                  onClick={() => {
                    setPreviewUrl(null)
                    setSelectedFile(null)
                    setResult(null)
                    setError(null)
                    if (fileInputRef.current) fileInputRef.current.value = ''
                  }}
                  className="absolute top-2 right-2 w-8 h-8 rounded-full bg-[#ff3366]/20 text-[#ff3366] flex items-center justify-center hover:bg-[#ff3366]/30 transition-colors"
                >
                  ✕
                </button>
              </div>

              <button
                onClick={handleAnalyze}
                disabled={isLoading}
                className={`w-full py-3 rounded-lg font-bold text-sm transition-all flex items-center justify-center gap-2 ${
                  isLoading
                    ? 'bg-[#1a1a2e] text-gray-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-[#00ff88] to-[#ffcc00] text-black hover:shadow-lg hover:shadow-[#00ff88]/20'
                }`}
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <span>🔍</span>
                    Analyze QR Code
                  </>
                )}
              </button>
            </div>
          ) : (
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full py-8 border-2 border-dashed border-[#2a2a3e] rounded-lg text-gray-400 hover:text-white hover:border-[#00ff88]/50 transition-all flex flex-col items-center gap-2"
            >
              <span className="text-4xl">📤</span>
              <span className="font-medium">Click to upload QR code image</span>
              <span className="text-xs text-gray-500">PNG, JPG, WebP supported</span>
            </button>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-xl p-4">
          <p className="text-[#ff3366]">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Content Display */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div
                  className="w-12 h-12 rounded-lg flex items-center justify-center text-2xl"
                  style={{ backgroundColor: result.decoded.isSuspicious ? '#ff336620' : '#00ff8820' }}
                >
                  {getTypeIcon(result.decoded.type)}
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">
                    {result.decoded.type.charAt(0).toUpperCase() + result.decoded.type.slice(1)} Content
                  </h4>
                  <p className="text-sm text-gray-400">
                    {result.decoded.isSuspicious ? '⚠️ Suspicious content detected' : '✅ Content appears safe'}
                  </p>
                </div>
              </div>
              {result.decoded.isSuspicious && (
                <div className="px-3 py-1 rounded-lg bg-[#ff3366]/20 text-[#ff3366] text-sm font-bold">
                  SUSPICIOUS
                </div>
              )}
            </div>

            <div className="p-6">
              <div className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                <div className="text-xs text-gray-400 mb-2">Decoded Content</div>
                <div className="font-mono text-white break-all">
                  {result.decoded.value}
                </div>
              </div>

              {result.decoded.type === 'url' && (
                <div className="mt-4 flex gap-2">
                  <a
                    href={result.decoded.value}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded-lg bg-[#ff3366]/20 text-[#ff3366] text-sm font-bold hover:bg-[#ff3366]/30 transition-colors"
                  >
                    ⚠️ DO NOT VISIT
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Threat Indicators */}
          {result.decoded.threatIndicators.length > 0 && (
            <div className="bg-[#111119] rounded-xl border border-[#ff3366]/30 overflow-hidden">
              <div className="bg-[#ff3366]/10 px-4 py-3 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#ff3366]/20 flex items-center justify-center">
                  <span className="text-xl">🚩</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-[#ff3366]">Threat Indicators</h4>
                  <p className="text-sm text-gray-400">{result.decoded.threatIndicators.length} indicator(s) found</p>
                </div>
              </div>
              <div className="p-4 space-y-3">
                {result.decoded.threatIndicators.map((indicator, i) => (
                  <div key={i} className="bg-[#0a0a0f] rounded-lg p-4 border border-[#1a1a2e]">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="px-2 py-0.5 rounded text-xs font-bold uppercase"
                            style={{
                              backgroundColor: `${getSeverityColor(indicator.severity)}20`,
                              color: getSeverityColor(indicator.severity)
                            }}
                          >
                            {indicator.severity}
                          </span>
                          <span className="text-xs text-gray-500 uppercase">{indicator.type.replace(/_/g, ' ')}</span>
                        </div>
                        <p className="text-gray-300 text-sm">{indicator.description}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
            <div className="bg-[#1a1a2e] px-4 py-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#ffcc00]/10 border border-[#ffcc00]/30 flex items-center justify-center">
                <span className="text-xl">💡</span>
              </div>
              <div>
                <h4 className="text-lg font-bold text-white">Recommendations</h4>
              </div>
            </div>
            <div className="p-4">
              <ul className="space-y-3">
                {result.decoded.isSuspicious ? (
                  <>
                    <li className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#ff3366]/20 text-[#ff3366] flex items-center justify-center text-sm font-bold">1</span>
                      <span className="text-gray-300">Do not scan this QR code with sensitive apps (banking, email)</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#ffcc00]/20 text-[#ffcc00] flex items-center justify-center text-sm font-bold">2</span>
                      <span className="text-gray-300">Verify the source of this QR code before scanning</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#00ccff]/20 text-[#00ccff] flex items-center justify-center text-sm font-bold">3</span>
                      <span className="text-gray-300">If you already scanned it, monitor your accounts for unusual activity</span>
                    </li>
                  </>
                ) : (
                  <>
                    <li className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#00ff88]/20 text-[#00ff88] flex items-center justify-center text-sm font-bold">1</span>
                      <span className="text-gray-300">QR code content appears legitimate</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#00ff88]/20 text-[#00ff88] flex items-center justify-center text-sm font-bold">2</span>
                      <span className="text-gray-300">Still verify the destination URL matches expected content</span>
                    </li>
                  </>
                )}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!result && !error && !isLoading && (
        <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] p-12 text-center">
          <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-[#1a1a2e] flex items-center justify-center">
            <span className="text-4xl">📱</span>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">QR Code Analyzer</h3>
          <p className="text-gray-400 max-w-md mx-auto">
            Upload a QR code image to decode its content and check for malicious destinations
          </p>
        </div>
      )}
    </div>
  )
}
