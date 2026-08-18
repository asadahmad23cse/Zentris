import path from "path";
import { fileURLToPath } from "url";

/** @type {import('next').NextConfig} */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const nextConfig = {
  // "standalone" is for Docker self-hosting; Vercel uses its own output pipeline.
  // Set BUILD_STANDALONE=true in Dockerfile to activate standalone mode.
  output: process.env.BUILD_STANDALONE === "true" ? "standalone" : undefined,
  basePath: "",
  assetPrefix: "",
  async rewrites() {
    return [
      {
        source: "/ui",
        destination: "/",
      },
      {
        source: "/ui/:path*",
        destination: "/:path*",
      },
    ];
  },
  turbopack: {
    // Must be absolute; "." is no longer allowed
    root: __dirname,
  },
};

export default nextConfig;
