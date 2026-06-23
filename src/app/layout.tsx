import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ThreatAnalyzer v1.0',
  description: 'Threat analysis engine — URL, domain, hash, email, WHOIS, and OSINT intelligence',
  icons: {
    icon: '/favicon.svg',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0a0a0f] text-gray-100 font-mono antialiased">
        {children}
      </body>
    </html>
  )
}