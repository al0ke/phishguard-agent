'use client'

import { useState, useRef } from 'react'
import jsQR from 'jsqr'
import { logAudit, saveLastResult } from '@/lib/analystClient'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'

export default function QrAnalyzer({ onInvestigate }: AnalyzerShellProps) {
  const [imageUrl, setImageUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setLoading(true)
    setError(null)
    setResult(null)

    const reader = new FileReader()
    reader.onload = async () => {
      const base64 = reader.result as string
      setImageUrl(base64)

      // Decode QR client-side using jsQR
      try {
        const img = new Image()
        img.onload = async () => {
          const canvas = document.createElement('canvas')
          const ctx = canvas.getContext('2d')
          if (!ctx) { setError('Canvas not supported'); setLoading(false); return }

          canvas.width = img.width
          canvas.height = img.height
          ctx.drawImage(img, 0, 0)

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
          const decoded = jsQR(imageData.data, imageData.width, imageData.height)

          if (!decoded || !decoded.data) {
            setError('No QR code found in image')
            setLoading(false)
            return
          }

          const qrUrl = decoded.data

          // If it looks like a URL, analyze it
          if (qrUrl.startsWith('http://') || qrUrl.startsWith('https://')) {
            try {
              const analyzeRes = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ input: qrUrl }),
              })
              if (analyzeRes.ok) {
                const analysis = await analyzeRes.json()
                setResult({ qrUrl, analysis })
                await logAudit({
                  tool: 'QR',
                  target: qrUrl,
                  riskScore: analysis.riskScore,
                  threatLevel: analysis.threatLevel,
                  findings: ['QR decoded to URL', analysis.feedMatch?.matched ? 'Threat feed match' : ''].filter(Boolean),
                })
                saveLastResult({
                  type: 'QR',
                  target: qrUrl,
                  timestamp: new Date().toISOString(),
                  riskScore: analysis.riskScore,
                  threatLevel: analysis.threatLevel,
                  findings: ['Quishing — QR payload decoded'],
                  recommendations: analysis.aiVerdict?.recommendations || [],
                  iocs: { ips: [], domains: [], urls: [qrUrl], hashes: [] },
                  raw: { qrUrl, analysis },
                })
              } else {
                setResult({ qrUrl, analysis: null })
              }
            } catch {
              setResult({ qrUrl, analysis: null })
            }
          } else {
            setResult({ qrUrl: null, text: qrUrl })
          }
          setLoading(false)
        }
        img.onerror = () => { setError('Failed to load image'); setLoading(false) }
        img.src = base64
      } catch {
        setError('Failed to process QR code')
        setLoading(false)
      }
    }
    reader.readAsDataURL(file)
  }

  return (
    <div className="space-y-4">
      <div
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-[#1a1a2e] rounded-xl p-8 text-center cursor-pointer hover:border-[#00ff88]/50 transition-colors"
      >
        {imageUrl ? (
          <img src={imageUrl} alt="QR Code" className="max-h-48 mx-auto rounded-lg" />
        ) : (
          <>
            <div className="w-16 h-16 mx-auto mb-3 rounded-full bg-[#1a1a2e] flex items-center justify-center">
              <span className="text-3xl">📷</span>
            </div>
            <p className="text-sm text-gray-400">Click to upload QR code image</p>
            <p className="text-xs text-gray-600 mt-1">PNG, JPG, WEBP</p>
          </>
        )}
        <input ref={fileInputRef} type="file" accept="image/*" onChange={handleFile} className="hidden" />
      </div>

      {loading && <p className="text-sm text-[#00ff88] text-center">Decoding QR code...</p>}
      {error && <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 text-red-400 text-sm">{error}</div>}

      {result && (
        <div className="space-y-3">
          {result.qrUrl && (
            <div className="bg-[#111119] border border-[#00ff88]/30 rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Decoded URL</p>
              <p className="text-sm font-mono text-[#00ff88] break-all">{result.qrUrl}</p>
              {onInvestigate && (
                <button type="button" onClick={() => onInvestigate('url', result.qrUrl)} className="text-xs text-[#00ccff] underline mt-2">
                  Investigate URL in URL Scan →
                </button>
              )}
            </div>
          )}

          {result.text && !result.qrUrl && (
            <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Decoded Text</p>
              <p className="text-sm font-mono text-white">{result.text}</p>
            </div>
          )}

          {result.analysis && (
            <div className="space-y-2">
              <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-4 text-center">
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Risk Score</p>
                <p className={`text-3xl font-bold ${
                  result.analysis.riskScore >= 70 ? 'text-[#ff3366]' :
                  result.analysis.riskScore >= 50 ? 'text-[#ffcc00]' :
                  result.analysis.riskScore >= 30 ? 'text-[#ff9900]' : 'text-[#00ff88]'
                }`}>{result.analysis.riskScore}<span className="text-sm text-gray-500">/100</span></p>
                <p className="text-sm font-bold uppercase mt-1 text-white">{result.analysis.threatLevel}</p>
              </div>

              {result.analysis.overallVerdict && (
                <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
                  <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Verdict</p>
                  <p className="text-sm text-gray-300">{result.analysis.overallVerdict}</p>
                </div>
              )}

              {result.analysis.iocs && (
                <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3">
                  <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">IOCs Found</p>
                  <div className="grid grid-cols-2 gap-2 text-center">
                    <div><p className="text-xs text-gray-400">IPs</p><p className="text-sm text-white">{result.analysis.iocs.ips?.length || 0}</p></div>
                    <div><p className="text-xs text-gray-400">Domains</p><p className="text-sm text-white">{result.analysis.iocs.domains?.length || 0}</p></div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3 text-xs text-gray-400">
        <p className="text-[#00ff88] font-bold mb-1">QR PHISHING (QUISHING)</p>
        <p>Upload a QR code → decoded client-side → URL auto-analyzed for phishing/malware.</p>
      </div>
    </div>
  )
}