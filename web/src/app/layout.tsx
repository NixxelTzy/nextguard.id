import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'NextGuard — Enterprise WAF',
  description: 'Enterprise-grade L7 web application firewall for Node.js. Zero config, full protection.',
  keywords: ['WAF', 'firewall', 'security', 'Node.js', 'middleware'],
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
