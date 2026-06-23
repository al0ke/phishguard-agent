'use client'

import { useState, useCallback, useRef } from 'react'
import type { AnalyzerShellProps } from '@/lib/analyzerProps'
import { logAudit } from '@/lib/analystClient'

type ViewportPreset = 'desktop' | 'tablet' | 'mobile'

const VIEWPORTS: Record<ViewportPreset, { width: number; height: number; label: string; icon: string }> = {
  desktop: { width: 1920, height: 1080, label: 'Desktop', icon: '🖥' },
  tablet: { width: 768, height: 1024, label: 'Tablet', icon: '📱' },
  mobile: { width: 375, height: 812, label: 'Mobile', icon: '📲' },
}

interface ScreenshotResult {
  success: boolean
  screenshot: string
  url: string
  title?: string
  capturedAt: string
  error?: string
}

export default function ScreenshotCapture({ onInvestigate }: AnalyzerShellProps) {
  const [url, setUrl] = useState('')
  const [viewport, setViewport] = useState<ViewportPreset>('desktop')
  const [fullPage, setFullPage] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScreenshotResult | null>(null)
  const [zoomed, setZoomed] = useState(false)
  const [copied, setCopied] = useState(false)
  const [downloaded, setDownloaded] = useState(false)
  const imgRef = useRef<HTMLImageElement>(null)

  const capture = useCallback(async () => {
    const trimmed = url.trim()
    if (!trimmed) return

    // Auto-prepend https:// if missing scheme
    const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`

    setLoading(true)
    setResult(null)
    setCopied(false)
    setDownloaded(false)

    try {
      const vp = VIEWPORTS[viewport]
      const res = await fetch('/api/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: normalized,
          width: vp.width,
          height: vp.height,
          fullPage,
        }),
      })
      const data: ScreenshotResult = await res.json()

      if (!data.success) {
        setResult(data)
      } else {
        setResult(data)
        // Log to audit trail
        logAudit({
          tool: 'SCREENSHOT',
          target: normalized,
          findings: [`Captured ${vp.label} ${fullPage ? 'full-page' : 'viewport'} screenshot`],
        })
      }
    } catch {
      setResult({
        success: false,
        screenshot: '',
        url: normalized,
        capturedAt: new Date().toISOString(),
        error: 'Network error — failed to reach screenshot API',
      })
    } finally {
      setLoading(false)
    }
  }, [url, viewport, fullPage])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !loading) capture()
  }

  const download = useCallback(() => {
    if (!result?.screenshot) return
    const link = document.createElement('a')
    link.href = result.screenshot
    const safeName = result.url.replace(/^https?:\/\//, '').replace(/[^a-z0-9]/gi, '_').slice(0, 60)
    link.download = `screenshot_${safeName}_${Date.now()}.png`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    setDownloaded(true)
    setTimeout(() => setDownloaded(false), 2000)
  }, [result])

  const copyToClipboard = useCallback(async () => {
    if (!result?.screenshot) return
    try {
      // Convert data URL to blob and write to clipboard
      const res = await fetch(result.screenshot)
      const blob = await res.blob()
      await navigator.clipboard.write([
        new ClipboardItem({ [blob.type]: blob }),
      ])
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback: copy the data URL string
      try {
        await navigator.clipboard.writeText(result.screenshot)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      } catch {
        /* clipboard not available */
      }
    }
  }, [result])

  const toggleZoom = () => setZoomed(z => !z)

  return (
    <div className="space-y-4">
      {/* Input section */}
      <div>
        <label className="text-xs text-gray-400 uppercase tracking-wide mb-1 block">
          URL to Capture
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com"
            className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
          />
          <button
            onClick={capture}
            disabled={loading || !url.trim()}
            className="px-6 py-2.5 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50 hover:bg-[#00ff88]/90 transition-colors whitespace-nowrap"
          >
            {loading ? '⏳ Capturing…' : '📸 Capture'}
          </button>
        </div>
      </div>

      {/* Options */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Viewport selector */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-gray-500 uppercase tracking-wide mr-1">Viewport</span>
          {(Object.keys(VIEWPORTS) as ViewportPreset[]).map(key => {
            const vp = VIEWPORTS[key]
            return (
              <button
                key={key}
                onClick={() => setViewport(key)}
                disabled={loading}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all disabled:opacity-50 ${
                  viewport === key
                    ? 'bg-[#00ccff]/10 border border-[#00ccff]/50 text-[#00ccff]'
                    : 'bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white'
                }`}
              >
                {vp.icon} {vp.label}
                <span className="text-[10px] text-gray-500 ml-1 font-mono">{vp.width}×{vp.height}</span>
              </button>
            )
          })}
        </div>

        {/* Full page toggle */}
        <button
          onClick={() => setFullPage(f => !f)}
          disabled={loading}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all disabled:opacity-50 ${
            fullPage
              ? 'bg-[#00ff88]/10 border border-[#00ff88]/50 text-[#00ff88]'
              : 'bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white'
          }`}
        >
          {fullPage ? '✓ ' : ''}Full Page
        </button>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <div className="inline-block w-8 h-8 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-3" />
          <p className="text-sm text-gray-400">Capturing screenshot…</p>
          <p className="text-xs text-gray-600 mt-1 font-mono">{url.trim()}</p>
        </div>
      )}

      {/* Error state */}
      {result && !result.success && (
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
          <div className="flex items-start gap-2">
            <span className="text-[#ff3366] text-lg">⚠</span>
            <div className="flex-1">
              <p className="text-[#ff3366] text-sm font-bold mb-1">Capture Failed</p>
              <p className="text-[#ff3366]/80 text-xs">{result.error}</p>
              {result.url && (
                <p className="text-gray-500 text-xs mt-2 font-mono break-all">{result.url}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Success result */}
      {result && result.success && result.screenshot && (
        <div className="space-y-3">
          {/* Metadata */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500 uppercase tracking-wide">Captured URL</span>
              <span className="text-[10px] text-gray-600 font-mono">
                {VIEWPORTS[viewport].label} {fullPage ? '· Full Page' : ''}
              </span>
            </div>
            <p className="text-xs text-white font-mono break-all">{result.url}</p>
            {result.title && (
              <>
                <div className="text-xs text-gray-500 uppercase tracking-wide mt-1">Page Title</div>
                <p className="text-xs text-[#00ccff]">{result.title}</p>
              </>
            )}
            <div className="flex items-center justify-between mt-1">
              <span className="text-xs text-gray-500 uppercase tracking-wide">Captured At</span>
              <span className="text-xs text-gray-400 font-mono">
                {new Date(result.capturedAt).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Screenshot image */}
          <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg overflow-hidden">
            <div
              className="relative cursor-zoom-in group bg-[#0a0a0f]"
              onClick={toggleZoom}
              style={{ minHeight: '100px' }}
            >
              <img
                ref={imgRef}
                src={result.screenshot}
                alt={`Screenshot of ${result.url}`}
                className={`w-full transition-all duration-200 ${
                  zoomed ? 'cursor-zoom-out scale-150' : 'cursor-zoom-in group-hover:opacity-90'
                }`}
                style={{ imageRendering: 'auto' }}
              />
              <div className="absolute top-2 right-2 px-2 py-1 rounded bg-black/60 text-[10px] text-gray-300 opacity-0 group-hover:opacity-100 transition-opacity">
                {zoomed ? 'Click to zoom out' : 'Click to zoom in'}
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={download}
              className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                downloaded
                  ? 'bg-[#00ff88]/10 border border-[#00ff88]/50 text-[#00ff88]'
                  : 'bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white'
              }`}
            >
              {downloaded ? '✓ Downloaded' : '⬇ Download PNG'}
            </button>
            <button
              onClick={copyToClipboard}
              className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                copied
                  ? 'bg-[#00ff88]/10 border border-[#00ff88]/50 text-[#00ff88]'
                  : 'bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white'
              }`}
            >
              {copied ? '✓ Copied' : '📋 Copy to Clipboard'}
            </button>
            <button
              onClick={capture}
              className="px-4 py-2 rounded-lg text-xs font-bold bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white transition-all"
            >
              🔄 Re-capture
            </button>
            {onInvestigate && (
              <button
                onClick={() => onInvestigate('url', result.url)}
                className="px-4 py-2 rounded-lg text-xs font-bold bg-[#00ccff]/10 border border-[#00ccff]/30 text-[#00ccff] hover:bg-[#00ccff]/20 transition-all"
              >
                🔍 Send to URL Scan
              </button>
            )}
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <div className="text-3xl mb-2">📸</div>
          <p className="text-sm text-gray-400">Enter a URL above to capture a screenshot</p>
          <p className="text-xs text-gray-600 mt-1">
            Supports desktop, tablet, and mobile viewports — useful for evidence collection
          </p>
        </div>
      )}
    </div>
  )
}