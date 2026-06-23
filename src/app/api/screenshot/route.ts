import { NextRequest, NextResponse } from 'next/server'

interface ScreenshotRequest {
  url: string
  width?: number
  height?: number
  fullPage?: boolean
}

interface ScreenshotResponse {
  success: boolean
  screenshot: string
  url: string
  title?: string
  capturedAt: string
  error?: string
}

function isValidUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false
  const trimmed = url.trim()
  if (!/^https?:\/\//i.test(trimmed)) return false
  try {
    new URL(trimmed)
    return true
  } catch {
    return false
  }
}

async function fetchWithTimeout(
  input: string | URL,
  init?: RequestInit,
  timeoutMs = 10000
): Promise<Response> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(input, {
      ...init,
      signal: controller.signal,
    })
    clearTimeout(timeoutId)
    return res
  } catch (err) {
    clearTimeout(timeoutId)
    throw err
  }
}

/**
 * Strategy 1: Use microlink.io API.
 * GET https://api.microlink.io/?url=<url>&screenshot=true&meta=false&viewport.width=<w>&viewport.height=<h>&screenshot.fullPage=<bool>&embed=screenshot.url
 * Returns JSON with screenshot data. When embed=screenshot.url, the response
 * contains the screenshot as a base64 data URI.
 */
async function captureWithMicrolink(
  url: string,
  width: number,
  height: number,
  fullPage: boolean
): Promise<{ base64: string; title?: string }> {
  const apiUrl = `https://api.microlink.io/?url=${encodeURIComponent(url)}&screenshot=true&meta=false&viewport.width=${width}&viewport.height=${height}&screenshot.fullPage=${fullPage}&embed=screenshot.url`
  const res = await fetchWithTimeout(apiUrl, {}, 10000)
  if (!res.ok) {
    throw new Error(`microlink API returned ${res.status}`)
  }
  const data = await res.json()
  if (data.status !== 'success' || !data.data?.screenshot) {
    throw new Error(data.message || 'microlink: no screenshot in response')
  }
  const screenshotUrl = data.data.screenshot.url
  if (!screenshotUrl) {
    throw new Error('microlink: screenshot URL missing')
  }
  // If embed worked, screenshot.url is already a data URI
  if (typeof screenshotUrl === 'string' && screenshotUrl.startsWith('data:image/')) {
    return { base64: screenshotUrl }
  }
  // Otherwise fetch the image URL
  const imgRes = await fetchWithTimeout(screenshotUrl, {}, 10000)
  if (!imgRes.ok) {
    throw new Error(`Failed to fetch screenshot image: ${imgRes.status}`)
  }
  const buf = Buffer.from(await imgRes.arrayBuffer())
  const mime = imgRes.headers.get('content-type') || 'image/png'
  return { base64: `data:${mime};base64,${buf.toString('base64')}` }
}

/**
 * Strategy 2: Use image.thum.io — free screenshot API, no key needed.
 * GET https://image.thum.io/get/width/<w>/<url>
 * Returns image bytes directly.
 */
async function captureWithThum(
  url: string,
  width: number
): Promise<{ base64: string; title?: string }> {
  const thumUrl = `https://image.thum.io/get/width/${width}/${url}`
  const res = await fetchWithTimeout(thumUrl, {}, 10000)
  if (!res.ok) {
    throw new Error(`thum.io returned ${res.status}`)
  }
  const buf = Buffer.from(await res.arrayBuffer())
  const mime = res.headers.get('content-type') || 'image/png'
  if (!mime.startsWith('image/')) {
    throw new Error('thum.io did not return an image')
  }
  return { base64: `data:${mime};base64,${buf.toString('base64')}` }
}

/**
 * Strategy 3: Fetch page HTML to extract title, then use thum.io for image.
 */
async function fetchPageTitle(url: string): Promise<string | undefined> {
  try {
    const res = await fetchWithTimeout(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; AnalystToolkit/2.1)' },
    }, 8000)
    const html = await res.text()
    const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i)
    return titleMatch?.[1]?.trim()
  } catch {
    return undefined
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json() as ScreenshotRequest
    const { url, width = 1920, height = 1080, fullPage = false } = body

    if (!isValidUrl(url)) {
      return NextResponse.json<ScreenshotResponse>(
        {
          success: false,
          screenshot: '',
          url: url || '',
          capturedAt: new Date().toISOString(),
          error: 'Invalid URL — must start with http:// or https://',
        },
        { status: 400 }
      )
    }

    const capturedAt = new Date().toISOString()
    const normalizedUrl = url.trim()

    // Fetch title in parallel with screenshot
    const [titleResult, captureResult] = await Promise.allSettled([
      fetchPageTitle(normalizedUrl),
      captureWithMicrolink(normalizedUrl, width, height, fullPage)
        .catch(() => captureWithThum(normalizedUrl, width)),
    ])

    const title = titleResult.status === 'fulfilled' ? titleResult.value : undefined

    if (captureResult.status === 'rejected' || !captureResult.value) {
      const errMsg = captureResult.status === 'rejected'
        ? String(captureResult.reason?.message || captureResult.reason)
        : 'Unknown capture error'
      return NextResponse.json<ScreenshotResponse>(
        {
          success: false,
          screenshot: '',
          url: normalizedUrl,
          title,
          capturedAt,
          error: `Screenshot capture failed: ${errMsg}`,
        },
        { status: 502 }
      )
    }

    return NextResponse.json<ScreenshotResponse>({
      success: true,
      screenshot: captureResult.value.base64,
      url: normalizedUrl,
      title: title || captureResult.value.title,
      capturedAt,
    })
  } catch (error) {
    console.error('Screenshot API error:', error)
    return NextResponse.json<ScreenshotResponse>(
      {
        success: false,
        screenshot: '',
        url: '',
        capturedAt: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Internal server error',
      },
      { status: 500 }
    )
  }
}

export async function GET() {
  return NextResponse.json({
    endpoint: '/api/screenshot',
    method: 'POST',
    description: 'Capture a screenshot of a URL',
    body: { url: 'string (required)', width: 'number (default 1920)', height: 'number (default 1080)', fullPage: 'boolean (default false)' },
  })
}