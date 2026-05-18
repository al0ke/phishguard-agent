import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PhishGuard Agent | AI-Powered Phishing Threat Analysis',
  description: 'Detect malicious URLs, email threats, and brand impersonation with AI-powered threat intelligence',
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