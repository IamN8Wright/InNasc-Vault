import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://vault.innasc.com'),
  title: 'InNasc Vault',
  description: 'An encrypted client technology and credential vault by InNasc.',
  icons: {
    icon: [
      { url: '/favicon-dark.png', media: '(prefers-color-scheme: dark)' },
      { url: '/favicon-light.png', media: '(prefers-color-scheme: light)' },
    ],
  },
  openGraph: {
    title: 'InNasc Vault',
    description: 'Systems in context. An encrypted client technology and credential vault.',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: 'InNasc Vault — Systems in context.' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'InNasc Vault',
    description: 'Systems in context. An encrypted client technology and credential vault.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
