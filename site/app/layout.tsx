import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Mosaic Database — branchable Postgres for agents (Alpha)",
  description: "Managed PostgreSQL with instant branches, governed SQL, and asynchronous dark standbys.",
  metadataBase: new URL("https://database.mosaicos.com"),
  openGraph: { title: "Mosaic Database (Alpha)", description: "Branchable PostgreSQL for agents with governed SQL and explicit operational boundaries.", url: "https://database.mosaicos.com", siteName: "Mosaic", type: "website" },
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body className={`${geistSans.variable} ${geistMono.variable}`}>{children}<script defer src="/feedback.js" /></body></html>;
}
