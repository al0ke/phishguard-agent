import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  images: {
    // `images.domains` is deprecated in Next.js 16 in favor of `remotePatterns`
    remotePatterns: [
      { protocol: 'https', hostname: 'www.virustotal.com' },
      { protocol: 'https', hostname: 'urlhaus-api.abuse.ch' },
    ],
  },
  typescript: {
    // Type checking is enforced during build — see AGENTS.md for the fixed type errors.
    ignoreBuildErrors: false,
  },
  // Next.js 16 removed the `eslint` build option. Run `npm run lint` separately (ESLint CLI).
}

export default nextConfig
