import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ParsedHeader {
  name: string
  value: string
}

interface MIMEPart {
  headers: ParsedHeader[]
  body: string
  contentType: string
  charset?: string
  boundary?: string
  multipartType?: string
  isAttachment: boolean
  attachmentFilename?: string
  contentDisposition?: string
  encoding?: string // Content-Transfer-Encoding
}

interface ReceivedHop {
  raw: string
  from?: string
  by?: string
  with?: string
  id?: string
  timestamp?: string
  ip?: string
  hostname?: string
}

interface AuthResult {
  spf?: { result?: string; domain?: string }
  dkim?: { result?: string; domain?: string }
  dmarc?: { result?: string; policy?: string }
  raw?: string
}

interface Attachment {
  filename: string
  contentType: string
  size: number
  content?: string // base64 if small enough
  md5Hash: string
}

interface EmlResult {
  headers: Record<string, string | string[] | Record<string, string>>
  from: { address: string; displayName: string }
  to: string[]
  cc: string[]
  bcc: string[]
  replyTo?: string
  subject: string
  date: string
  messageId?: string
  returnPath?: string
  bodyText: string
  bodyHtml: string
  attachments: Attachment[]
  urls: string[]
  ips: string[]
  domains: string[]
  receivedPath: ReceivedHop[]
  authResults: AuthResult
  riskScore: number
  threatLevel: string
}

// ─── MIME Parsing Utilities ──────────────────────────────────────────────────

/** Decode Quoted-Printable encoded content */
function decodeQuotedPrintable(input: string): string {
  // Remove soft line breaks: '=' at end of line
  let str = input.replace(/=\r?\n/g, '')
  // Decode QP hex sequences, being careful not to decode = at end
  str = str.replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) =>
    String.fromCharCode(parseInt(hex, 16))
  )
  return str
}

/** Decode Base64 encoded content safely (handles multi-line base64) */
function decodeBase64(input: string): string {
  // Remove whitespace/newlines from base64
  const cleaned = input.replace(/\s/g, '')
  try {
    return Buffer.from(cleaned, 'base64').toString('utf-8')
  } catch {
    return input
  }
}

/** Decode base64 to raw Buffer (for attachments) */
function decodeBase64Raw(input: string): Buffer {
  const cleaned = input.replace(/\s/g, '')
  try {
    return Buffer.from(cleaned, 'base64')
  } catch {
    return Buffer.from(input, 'utf-8')
  }
}

/** Decode an RFC 2047 encoded-word header value, e.g. =?UTF-8?B?...?= */
function decodeEncodedWord(str: string): string {
  // Handle multiple encoded words concatenated
  return str.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g,
    (_, charset: string, encoding: string, content: string) => {
      try {
        if (encoding.toUpperCase() === 'B') {
          const decoded = Buffer.from(content, 'base64').toString('utf-8')
          return decoded
        } else {
          // Q-encoding: underscores = spaces, =XX hex
          const qDecoded = content
            .replace(/_/g, ' ')
            .replace(/=([0-9A-Fa-f]{2})/g, (_m: string, h: string) =>
              String.fromCharCode(parseInt(h, 16))
            )
          return qDecoded
        }
      } catch {
        return content
      }
    }
  )
}

/** Decode body based on Content-Transfer-Encoding */
function decodeBody(body: string, encoding?: string): string {
  if (!encoding) return body
  const enc = encoding.toLowerCase().trim()
  if (enc === 'base64') return decodeBase64(body)
  if (enc === 'quoted-printable') return decodeQuotedPrintable(body)
  if (enc === '7bit' || enc === '8bit' || enc === 'binary') return body
  return body
}

/** Split raw eml into header section and body section */
function splitHeadersAndBody(raw: string): { headerText: string; bodyText: string } {
  // Headers and body are separated by first blank line (\r\n\r\n or \n\n)
  const idx = raw.search(/\r?\n\r?\n/)
  if (idx === -1) {
    return { headerText: raw, bodyText: '' }
  }
  // Get the match to find the full blank-line length
  const match = raw.match(/\r?\n\r?\n/)
  const sepLength = match ? match[0].length : 4
  return {
    headerText: raw.slice(0, idx),
    bodyText: raw.slice(idx + sepLength),
  }
}

/** Parse raw header text into array of {name, value} (folding aware) */
function parseHeaders(headerText: string): ParsedHeader[] {
  const headers: ParsedHeader[] = []
  // Normalize line endings
  const lines = headerText.replace(/\r\n/g, '\n').split('\n')
  let currentHeader: ParsedHeader | null = null

  for (const line of lines) {
    // Continuation line: starts with space or tab → folded into previous header
    if (/^[ \t]/.test(line) && currentHeader) {
      currentHeader.value += ' ' + line.trim()
    } else {
      // New header
      const colonIdx = line.indexOf(':')
      if (colonIdx === -1) continue
      const name = line.slice(0, colonIdx).trim()
      const value = line.slice(colonIdx + 1).trim()
      if (currentHeader) headers.push(currentHeader)
      currentHeader = { name, value }
    }
  }
  if (currentHeader) headers.push(currentHeader)
  return headers
}

/** Get a single header value (first occurrence) from parsed headers */
function getHeader(headers: ParsedHeader[], name: string): string | undefined {
  const h = headers.find(h => h.name.toLowerCase() === name.toLowerCase())
  return h ? h.value : undefined
}

/** Parse Content-Type header into { value, params } */
function parseContentType(headerValue: string): {
  value: string
  params: Record<string, string>
} {
  if (!headerValue) return { value: '', params: {} }
  const parts = headerValue.split(';')
  const value = parts[0].trim().toLowerCase()
  const params: Record<string, string> = {}
  for (let i = 1; i < parts.length; i++) {
    const eqIdx = parts[i].indexOf('=')
    if (eqIdx === -1) continue
    const key = parts[i].slice(0, eqIdx).trim().toLowerCase()
    let val = parts[i].slice(eqIdx + 1).trim()
    // Remove surrounding quotes
    val = val.replace(/^"/, '').replace(/"$/, '')
    params[key] = val
  }
  return { value, params }
}

/** Extract email address from a From/To/Reply-To header value */
function extractEmailAddress(headerValue: string): {
  address: string
  displayName: string
} {
  if (!headerValue) return { address: '', displayName: '' }
  const decoded = decodeEncodedWord(headerValue)
  // Try "Display Name" <email@domain.com>
  let match = decoded.match(/<([^>]+)>\s*$/)
  if (match) {
    let displayName = decoded.replace(/<[^>]+>\s*$/, '').trim()
    // Remove surrounding quotes
    displayName = displayName.replace(/^"/, '').replace(/"$/, '')
    return { address: match[1].trim(), displayName }
  }
  // Try Display Name <email@domain.com> without quotes
  match = decoded.match(/<([^>]+)>/)
  if (match) {
    let displayName = decoded.replace(/<[^>]+>/, '').trim()
    displayName = displayName.replace(/^"/, '').replace(/"$/, '')
    return { address: match[1].trim(), displayName }
  }
  // Bare email address
  match = decoded.match(/([^\s]+@[^\s]+)/)
  if (match) {
    return { address: match[1], displayName: '' }
  }
  return { address: decoded.trim(), displayName: '' }
}

/** Extract all email addresses from a comma-separated To/Cc/Bcc header */
function extractAllAddresses(headerValue: string): string[] {
  if (!headerValue) return []
  const decoded = decodeEncodedWord(headerValue)
  const addresses: string[] = []
  // Split by commas (but not inside angle brackets)
  const parts = decoded.split(/,(?![^<]*>)/)
  for (const part of parts) {
    const { address } = extractEmailAddress(part.trim())
    if (address) addresses.push(address)
  }
  return addresses
}

/** Extract domain from an email address */
function extractDomain(email: string): string | null {
  if (!email) return null
  const atIdx = email.lastIndexOf('@')
  if (atIdx === -1) return null
  return email.slice(atIdx + 1).toLowerCase()
}

/** Split a multipart body by boundary */
function splitMultipart(body: string, boundary: string): string[] {
  // The boundary delimiter is: --<boundary>
  // The final delimiter is: --<boundary>--
  const delimiter = '--' + boundary
  // Split on delimiter
  const parts = body.split(delimiter)
  // The first part (before the first delimiter) and last part (after closing --) are non-content
  const result: string[] = []
  for (let i = 1; i < parts.length; i++) {
    let part = parts[i]
    // Skip the closing delimiter part (starts with --)
    if (part.startsWith('--')) continue
    // Remove leading CRLF/LF after the boundary line
    part = part.replace(/^\r?\n/, '')
    // Remove trailing CRLF/LF before the next boundary
    part = part.replace(/\r?\n$/, '')
    result.push(part)
  }
  return result
}

/** Parse a single MIME part (sub-headers + body) */
function parseMIMEPart(rawPart: string): MIMEPart {
  const { headerText, bodyText } = splitHeadersAndBody(rawPart)
  const headers = parseHeaders(headerText)

  const ctHeader = getHeader(headers, 'Content-Type') || ''
  const { value: contentType, params: ctParams } = parseContentType(ctHeader)

  const cteHeader = getHeader(headers, 'Content-Transfer-Encoding')
  const encoding = cteHeader ? cteHeader.toLowerCase().trim() : undefined

  const dispositionHeader = getHeader(headers, 'Content-Disposition') || ''
  const isAttachment =
    dispositionHeader.toLowerCase().includes('attachment') ||
    contentType.startsWith('application/') && !contentType.includes('name=') === false
  // More accurate attachment detection: if Content-Disposition has filename
  const hasFilename =
    dispositionHeader.toLowerCase().includes('filename') ||
    ctHeader.toLowerCase().includes('name=')

  const attachmentMatch =
    dispositionHeader.match(/filename="([^"]+)"/i) ||
    dispositionHeader.match(/filename=([^;\s]+)/i) ||
    ctHeader.match(/name="([^"]+)"/i) ||
    ctHeader.match(/name=([^;\s]+)/i)
  const attachmentFilename = attachmentMatch ? attachmentMatch[1] : undefined

  return {
    headers,
    body: bodyText,
    contentType: ctHeader,
    charset: ctParams.charset,
    boundary: ctParams.boundary,
    multipartType: contentType.startsWith('multipart/') ? contentType : undefined,
    isAttachment: isAttachment || (!!hasFilename && !contentType.startsWith('multipart/')),
    attachmentFilename: attachmentFilename || (hasFilename ? 'unnamed' : undefined),
    contentDisposition: dispositionHeader,
    encoding,
  }
}

/** Recursively walk MIME parts and collect text/html/attachments */
interface CollectedBodies {
  textParts: { content: string; charset?: string }[]
  htmlParts: { content: string; charset?: string }[]
  attachments: {
    filename: string
    contentType: string
    rawBody: string
    encoding?: string
  }[]
}

function collectBodies(rawPart: string, depth = 0): CollectedBodies {
  const result: CollectedBodies = { textParts: [], htmlParts: [], attachments: [] }
  if (depth > 20) return result // Safety limit

  const part = parseMIMEPart(rawPart)
  const ct = part.multipartType

  if (ct && ct.startsWith('multipart/') && part.boundary) {
    // Recurse into multipart sub-parts
    const subParts = splitMultipart(part.body, part.boundary)
    for (const subPart of subParts) {
      const subResult = collectBodies(subPart, depth + 1)
      result.textParts.push(...subResult.textParts)
      result.htmlParts.push(...subResult.htmlParts)
      result.attachments.push(...subResult.attachments)
    }
    return result
  }

  // Single part
  const ctLower = part.contentType.toLowerCase()
  const isText = ctLower.includes('text/plain')
  const isHtml = ctLower.includes('text/html')
  const isAttachment = part.isAttachment

  if (isAttachment && part.attachmentFilename) {
    result.attachments.push({
      filename: part.attachmentFilename,
      contentType: ctLower.split(';')[0].trim(),
      rawBody: part.body,
      encoding: part.encoding,
    })
  } else if (isText) {
    result.textParts.push({
      content: decodeBody(part.body, part.encoding),
      charset: part.charset,
    })
  } else if (isHtml) {
    result.htmlParts.push({
      content: decodeBody(part.body, part.encoding),
      charset: part.charset,
    })
  } else if (!isText && !isHtml && ct && !ct.startsWith('multipart/')) {
    // Non-text, non-html, non-multipart → treat as attachment if has filename or is binary-ish
    if (part.attachmentFilename || ctLower.includes('application/')) {
      result.attachments.push({
        filename: part.attachmentFilename || 'unknown',
        contentType: ctLower.split(';')[0].trim(),
        rawBody: part.body,
        encoding: part.encoding,
      })
    }
  }

  return result
}

// ─── URL / IP / Domain Extraction ────────────────────────────────────────────

/** Extract all URLs from a text string */
function extractUrls(text: string): string[] {
  if (!text) return []
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi
  const matches = text.match(urlRegex) || []
  // Clean trailing punctuation
  const cleaned = matches.map(u => u.replace(/[.,;:!?)\]}>]+$/, ''))
  return [...new Set(cleaned)]
}

/** Extract URLs from HTML content (href attributes + bare URLs) */
function extractUrlsFromHtml(html: string): string[] {
  if (!html) return []
  const urls: string[] = []
  // href="..."
  const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi
  let match: RegExpExecArray | null
  while ((match = hrefRegex.exec(html)) !== null) {
    const url = match[1].trim()
    if (url.startsWith('http://') || url.startsWith('https://')) {
      urls.push(url)
    }
  }
  // Also catch bare URLs in HTML text
  urls.push(...extractUrls(html))
  return [...new Set(urls)]
}

/** Extract IP addresses from Received headers */
function extractIpsFromReceived(receivedHeaders: string[]): string[] {
  const ips: string[] = []
  const ipRegex =
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
  // Also IPv6 in brackets
  const ipv6Regex = /\[([0-9a-fA-F:]+)\]/g
  for (const header of receivedHeaders) {
    const matches = header.match(ipRegex) || []
    ips.push(...matches)
    let v6Match: RegExpExecArray | null
    while ((v6Match = ipv6Regex.exec(header)) !== null) {
      const ip = v6Match[1]
      if (ip.includes(':') && !ip.includes('.')) {
        ips.push(ip)
      }
    }
  }
  return [...new Set(ips)]
}

/** Extract domains from URLs */
function extractDomainsFromUrls(urls: string[]): string[] {
  const domains: string[] = []
  for (const url of urls) {
    try {
      const u = new URL(url)
      if (u.hostname) domains.push(u.hostname.toLowerCase())
    } catch {
      // Not a valid URL, try regex
      const match = url.match(/https?:\/\/([^/]+)/i)
      if (match) domains.push(match[1].toLowerCase())
    }
  }
  return domains
}

// ─── Received Header & Auth Parsing ─────────────────────────────────────────

/** Parse a single Received header into structured data */
function parseReceivedHeader(raw: string): ReceivedHop {
  const hop: ReceivedHop = { raw }

  // "from" sender
  const fromMatch = raw.match(/from\s+([^\s]+(?:\s+\([^)]+\))?)/i)
  if (fromMatch) hop.from = fromMatch[1].trim()

  // "by" receiver
  const byMatch = raw.match(/by\s+([^\s]+(?:\s+\([^)]+\))?)/i)
  if (byMatch) hop.by = byMatch[1].trim()

  // "with" protocol
  const withMatch = raw.match(/with\s+([^\s;]+)/i)
  if (withMatch) hop.with = withMatch[1].trim()

  // "id" identifier
  const idMatch = raw.match(/\bid\s+([^\s;]+)/i)
  if (idMatch) hop.id = idMatch[1].trim()

  // Extract hostname from "from" field
  if (hop.from) {
    // Try to extract hostname from "from sender (hostname [ip])"
    const hostnameMatch = hop.from.match(/\(([^()]+)\)/)
    if (hostnameMatch) {
      hop.hostname = hostnameMatch[1].trim()
    } else {
      hop.hostname = hop.from.replace(/[\[\]()]/g, '').trim()
    }
  }

  // Extract IP from "from" field
  const ipMatch = raw.match(
    /\[((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\]/
  )
  if (ipMatch) {
    hop.ip = ipMatch[1]
  }

  // Timestamp: everything after the last semicolon
  const semiIdx = raw.lastIndexOf(';')
  if (semiIdx !== -1) {
    hop.timestamp = raw.slice(semiIdx + 1).trim()
  }

  return hop
}

/** Parse Authentication-Results header */
function parseAuthResults(authHeader: string | undefined): AuthResult {
  if (!authHeader) return {}
  const result: AuthResult = { raw: authHeader }

  // SPF: "spf=pass" or "spf=fail" etc.
  const spfMatch = authHeader.match(/spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)/i)
  if (spfMatch) {
    result.spf = { result: spfMatch[1].toLowerCase() }
    const spfDomainMatch = authHeader.match(/spf\s*=\s*\w+\s*\((?:mail\.)?from:([^)]+)\)/i)
    if (spfDomainMatch) result.spf.domain = spfDomainMatch[1].trim()
  }

  // DKIM: "dkim=pass" or "dkim=fail" etc.
  const dkimMatch = authHeader.match(/dkim\s*=\s*(pass|fail|neutral|none|temperror|permerror|policy|discard)/i)
  if (dkimMatch) {
    result.dkim = { result: dkimMatch[1].toLowerCase() }
    const dkimDomainMatch = authHeader.match(/dkim\s*=\s*\w+\s*\((?:header\.)?[id@=]*\s*([^)\s]+)/i)
    if (dkimDomainMatch) result.dkim.domain = dkimDomainMatch[1].replace(/d=/, '').trim()
    // Also try d=domain pattern
    const dMatch = authHeader.match(/d\s*=\s*([^\s;)]+)/i)
    if (dMatch && !result.dkim.domain) result.dkim.domain = dMatch[1].trim()
  }

  // DMARC: "dmarc=pass" or "dmarc=fail" etc.
  const dmarcMatch = authHeader.match(/dmarc\s*=\s*(pass|fail|quarantine|reject|none)/i)
  if (dmarcMatch) {
    result.dmarc = { result: dmarcMatch[1].toLowerCase() }
    const policyMatch = authHeader.match(/p\s*=\s*(none|quarantine|reject)/i)
    if (policyMatch) result.dmarc.policy = policyMatch[1].toLowerCase()
  }

  return result
}

// ─── Risk Score Calculation ──────────────────────────────────────────────────

function calculateRiskScore(
  auth: AuthResult,
  domains: string[],
  attachments: Attachment[],
  urls: string[],
  receivedPath: ReceivedHop[]
): { score: number; level: string } {
  let score = 0

  // Authentication failures
  if (auth.spf) {
    if (auth.spf.result === 'fail' || auth.spf.result === 'softfail') score += 20
    else if (auth.spf.result === 'neutral' || auth.spf.result === 'none') score += 10
  } else {
    score += 15 // No SPF result at all
  }

  if (auth.dkim) {
    if (auth.dkim.result === 'fail' || auth.dkim.result === 'permerror') score += 20
    else if (auth.dkim.result === 'neutral' || auth.dkim.result === 'none') score += 5
  } else {
    score += 10 // No DKIM result
  }

  if (auth.dmarc) {
    if (auth.dmarc.result === 'fail') score += 15
    else if (auth.dmarc.result === 'quarantine') score += 10
    else if (auth.dmarc.policy === 'none') score += 3
  } else {
    score += 5 // No DMARC
  }

  // Suspicious domains (look for suspicious TLDs or patterns)
  const suspiciousTlds = ['.zip', '.mov', '.xyz', '.top', '.click', '.link', '.country', '.work', '.gq', '.tk', '.ml', '.cf', '.ga']
  const suspiciousDomains = domains.filter(d =>
    suspiciousTlds.some(tld => d.endsWith(tld)) ||
    /^\d+\.\d+\.\d+\.\d+$/.test(d) // IP as domain
  )
  score += Math.min(suspiciousDomains.length * 8, 24)

  // Suspicious attachment types
  const dangerousExts = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar', '.msi', '.hta', '.ps1', '.zip', '.rar', '.7z']
  const dangerousAttachments = attachments.filter(a =>
    dangerousExts.some(ext => a.filename.toLowerCase().endsWith(ext))
  )
  score += Math.min(dangerousAttachments.length * 12, 24)

  // URL count (more URLs = higher risk)
  if (urls.length > 10) score += 15
  else if (urls.length > 5) score += 10
  else if (urls.length > 2) score += 5

  // Received path anomalies: if very few hops (possible direct injection)
  if (receivedPath.length <= 1) score += 5

  score = Math.min(score, 100)

  const level =
    score >= 80 ? 'critical' :
    score >= 60 ? 'high' :
    score >= 40 ? 'medium' :
    score >= 20 ? 'low' : 'safe'

  return { score, level }
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { content } = body as { content: string }

    if (!content || typeof content !== 'string') {
      return NextResponse.json(
        { error: 'Missing or invalid "content" field — expected raw .eml text' },
        { status: 400 }
      )
    }

    // Split headers and body
    const { headerText, bodyText } = splitHeadersAndBody(content)
    const parsedHeaders = parseHeaders(headerText)

    // Build headers object for response
    const headersObj: Record<string, string | string[]> = {}
    const receivedHeaders: string[] = []
    const xHeaders: Record<string, string> = {}

    for (const h of parsedHeaders) {
      const name = h.name
      if (name.toLowerCase() === 'received') {
        receivedHeaders.push(h.value)
      } else if (name.toLowerCase().startsWith('x-')) {
        xHeaders[name] = decodeEncodedWord(h.value)
      } else {
        // If already exists, make it an array
        if (name in headersObj) {
          const existing = headersObj[name]
          if (Array.isArray(existing)) {
            existing.push(h.value)
          } else {
            headersObj[name] = [existing, h.value]
          }
        } else {
          headersObj[name] = h.value
        }
      }
    }

    // Extract key headers
    const fromHeader = getHeader(parsedHeaders, 'From') || ''
    const toHeader = getHeader(parsedHeaders, 'To') || ''
    const ccHeader = getHeader(parsedHeaders, 'Cc') || ''
    const bccHeader = getHeader(parsedHeaders, 'Bcc') || ''
    const replyToHeader = getHeader(parsedHeaders, 'Reply-To') || ''
    const subjectHeader = getHeader(parsedHeaders, 'Subject') || ''
    const dateHeader = getHeader(parsedHeaders, 'Date') || ''
    const messageIdHeader = getHeader(parsedHeaders, 'Message-ID') || getHeader(parsedHeaders, 'Message-Id') || ''
    const returnPathHeader = getHeader(parsedHeaders, 'Return-Path') || ''
    const authHeader = getHeader(parsedHeaders, 'Authentication-Results') || ''

    // Parse From
    const { address: fromAddress, displayName: fromDisplayName } =
      extractEmailAddress(fromHeader)

    // Parse To/Cc/Bcc
    const toAddresses = extractAllAddresses(toHeader)
    const ccAddresses = extractAllAddresses(ccHeader)
    const bccAddresses = extractAllAddresses(bccHeader)

    // Parse top-level Content-Type to determine if multipart
    const topCtHeader = getHeader(parsedHeaders, 'Content-Type') || ''
    const { value: topCt, params: topCtParams } = parseContentType(topCtHeader)

    let bodyTextContent = ''
    let htmlContent = ''
    const attachmentList: Attachment[] = []

    if (topCt.startsWith('multipart/') && topCtParams.boundary) {
      // Multipart email — recurse into parts
      const collected = collectBodies(bodyText, 0)
      bodyTextContent = collected.textParts.map(p => p.content).join('\n\n')
      htmlContent = collected.htmlParts.map(p => p.content).join('\n\n')

      for (const att of collected.attachments) {
        const rawBuffer = att.encoding === 'base64'
          ? decodeBase64Raw(att.rawBody)
          : Buffer.from(decodeBody(att.rawBody, att.encoding), 'utf-8')
        const md5Hash = crypto.createHash('md5').update(rawBuffer).digest('hex')
        const attachment: Attachment = {
          filename: att.filename,
          contentType: att.contentType,
          size: rawBuffer.length,
          md5Hash,
        }
        // Include base64 content only if small (< 50KB)
        if (rawBuffer.length < 51200) {
          attachment.content = rawBuffer.toString('base64')
        }
        attachmentList.push(attachment)
      }
    } else {
      // Simple (non-multipart) email
      const topCte = getHeader(parsedHeaders, 'Content-Transfer-Encoding')
      if (topCt.includes('text/html')) {
        htmlContent = decodeBody(bodyText, topCte)
      } else {
        bodyTextContent = decodeBody(bodyText, topCte)
      }
    }

    // Extract URLs from body text and HTML
    const textUrls = extractUrls(bodyTextContent)
    const htmlUrls = extractUrlsFromHtml(htmlContent)
    const allUrls = [...new Set([...textUrls, ...htmlUrls])]

    // Parse Received headers into hops
    const receivedPath = receivedHeaders.map(h => parseReceivedHeader(h))

    // Extract IPs from Received headers
    const ips = extractIpsFromReceived(receivedHeaders)

    // Extract domains from From, To, Reply-To, and URLs
    const domainSet = new Set<string>()
    const fromDomain = extractDomain(fromAddress)
    if (fromDomain) domainSet.add(fromDomain)
    for (const to of toAddresses) {
      const d = extractDomain(to)
      if (d) domainSet.add(d)
    }
    if (replyToHeader) {
      const replyAddr = extractEmailAddress(replyToHeader)
      const d = extractDomain(replyAddr.address)
      if (d) domainSet.add(d)
    }
    if (returnPathHeader) {
      const d = extractDomain(returnPathHeader.replace(/[<>]/g, ''))
      if (d) domainSet.add(d)
    }
    for (const u of allUrls) {
      const domains = extractDomainsFromUrls([u])
      domains.forEach(d => domainSet.add(d))
    }

    const domains = [...domainSet]

    // Parse authentication results
    const authResults = parseAuthResults(authHeader)

    // Calculate risk score
    const { score: riskScore, level: threatLevel } = calculateRiskScore(
      authResults,
      domains,
      attachmentList,
      allUrls,
      receivedPath
    )

    // Decode subject for display
    const decodedSubject = decodeEncodedWord(subjectHeader)

    const result: EmlResult = {
      headers: {
        ...headersObj,
        Received: receivedHeaders,
        'X-Headers': xHeaders,
      },
      from: {
        address: fromAddress,
        displayName: fromDisplayName,
      },
      to: toAddresses,
      cc: ccAddresses,
      bcc: bccAddresses,
      replyTo: replyToHeader ? extractEmailAddress(replyToHeader).address : undefined,
      subject: decodedSubject,
      date: dateHeader,
      messageId: messageIdHeader || undefined,
      returnPath: returnPathHeader || undefined,
      bodyText: bodyTextContent,
      bodyHtml: htmlContent,
      attachments: attachmentList,
      urls: allUrls,
      ips,
      domains,
      receivedPath,
      authResults,
      riskScore,
      threatLevel,
    }

    return NextResponse.json(result)
  } catch (err) {
    console.error('EML parse error:', err)
    return NextResponse.json(
      { error: 'Failed to parse EML file: ' + (err instanceof Error ? err.message : 'unknown error') },
      { status: 500 }
    )
  }
}