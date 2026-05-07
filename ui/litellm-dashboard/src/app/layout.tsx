import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

import AntdGlobalProvider from "@/contexts/AntdGlobalProvider";
import ReactQueryProvider from "@/contexts/ReactQueryProvider";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Zentris Dashboard",
  description: "Zentris Proxy Admin UI",
  icons: { icon: "./favicon.ico" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <ReactQueryProvider>
          <AntdGlobalProvider>{children}</AntdGlobalProvider>
        </ReactQueryProvider>
      </body>
    </html>
  );
}


