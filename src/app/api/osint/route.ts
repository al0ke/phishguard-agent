import { NextRequest, NextResponse } from 'next/server'

const FIRECRAWL_KEY = process.env.FIRECRAWL_API_KEY || ''

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'URL required' }, { status: 400 })
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (FIRECRAWL_KEY && FIRECRAWL_KEY.startsWith('fc-')) {
      headers['Authorization'] = `Bearer ${FIRECRAWL_KEY}`
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 6000)
    const scrapeRes = await fetch('https://api.firecrawl.dev/v0/scrape', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        url,
        formats: ['markdown', 'metadata'],
        onlyMainContent: false,
      }),
      signal: controller.signal,
    })
    clearTimeout(timer)

    if (!scrapeRes.ok) {
      const errText = await scrapeRes.text()
      return NextResponse.json({
        error: `Firecrawl error ${scrapeRes.status}`,
        detail: errText,
      }, { status: 502 })
    }

    const data = await scrapeRes.json()

    const content = data.data || {}
    const metadata = content.metadata || {}

    // Extract emails from markdown
    const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g
    const emails = [...new Set((content.markdown || '').match(emailRegex) || [])]

    // Extract social links
    const socialPatterns = {
      twitter: /https?:\/\/(www\.)?(twitter\.com|x\.com)\/[a-zA-Z0-9_]+/g,
      linkedin: /https?:\/\/(www\.)?linkedin\.com\/in\/[a-zA-Z0-9\-]+/g,
      github: /https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9_\-]+/g,
      facebook: /https?:\/\/(www\.)?facebook\.com\/[a-zA-Z0-9.\-_]+/g,
      instagram: /https?:\/\/(www\.)?instagram\.com\/[a-zA-Z0-9._\-]+/g,
    }
    const social: Record<string, string[]> = {}
    const rawText = content.markdown || ''
    for (const [platform, regex] of Object.entries(socialPatterns)) {
      const matches: string[] = (rawText.match(regex) || []) as string[]
      if (matches.length > 0) social[platform] = [...new Set(matches)].slice(0, 5)
    }

    // Extract external domains
    const domainRegex = /https?:\/\/(?!www\.(?:google|facebook|linkedin|twitter|instagram)[.])[^\/\s]+/g
    const allUrls = rawText.match(domainRegex) || []
    const targetHost = new URL(url).hostname
    const domainHostnames: string[] = allUrls
      .map((u: string) => { try { return new URL(u).hostname } catch { return null } })
      .filter((d: string | null): d is string => d !== null && d !== targetHost)
    const externalDomains = [...new Set(domainHostnames)].slice(0, 20)

    // Extract tech stack from meta/generator tags
    const techKeywords = [
      'WordPress', 'React', 'Vue', 'Angular', 'Next.js', 'Node.js', 'Django',
      'Flask', 'Laravel', 'PHP', 'Ruby on Rails', 'AWS', 'Cloudflare', 'Shopify',
      'Stripe', 'Cloudflare', 'Google Analytics', 'Meta Pixel', 'jQuery',
      'Bootstrap', 'Tailwind', 'nginx', 'Apache', 'CloudFront', 'Vercel',
      'Netlify', 'Heroku', 'Firebase', 'Supabase', 'MongoDB', 'PostgreSQL',
    ]
    const foundTech = techKeywords.filter(t => rawText.toLowerCase().includes(t.toLowerCase()))

    // Extract external links count
    const allLinks = rawText.match(/https?:\/\/[^\s<>"\']+/g) || []
    const externalLinks = allLinks.filter((l: string) => {
      try { return !new URL(l).hostname.includes(new URL(url).hostname) } catch { return false }
    })

    return NextResponse.json({
      url,
      title: metadata.title || content.title || null,
      description: metadata.description || null,
      author: metadata.author || null,
      published: metadata.published || null,
      emails: emails.slice(0, 10),
      social,
      externalDomains,
      techStack: foundTech,
      linkCount: externalLinks.length,
      markdown: (content.markdown || '').slice(0, 3000),
      ogImage: metadata.ogImage || null,
    })
  } catch (err) {
    console.error('OSINT route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}
