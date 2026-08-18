import path from "path";
import { fileURLToPath } from "url";

/** @type {import('next').NextConfig} */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const nextConfig = {
  output: "standalone",
  // output: "export" removed — static export breaks dev server auth/routing
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
