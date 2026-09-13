import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Whisper — Private conversations",
  description: "A focused, end-to-end encrypted chat experience for private conversations.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
