import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import prettier from "eslint-config-prettier";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import unusedImports from "eslint-plugin-unused-imports";

export default defineConfig([
  globalIgnores([".next/**", "node_modules/**", "out/**", "build/**", "next-env.d.ts", "tsconfig.tsbuildinfo", "**/*.test.*", "tests/**"]),
  js.configs.recommended,
  ...nextVitals,
  ...nextTypescript,
  prettier,
  {
    plugins: { "unused-imports": unusedImports },
    rules: {
      "unused-imports/no-unused-imports": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "@typescript-eslint/ban-ts-comment": "off",
      "@typescript-eslint/no-require-imports": "off",
      "react/display-name": "off",
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/set-state-in-render": "off",
      "react-hooks/preserve-manual-memoization": "off",
      "react-hooks/incompatible-library": "off",
      "react-hooks/refs": "off",
      "react-hooks/immutability": "off",
      "react-hooks/purity": "off",
      "react-hooks/static-components": "off",
      "react-hooks/use-memo": "off",
      "prefer-const": "off",
      "no-empty": "off",
      "no-prototype-builtins": "off",
      "no-useless-catch": "off",
      "no-useless-escape": "off",
      "no-self-assign": "off",
      "react/no-unescaped-entities": "off",
      "no-constant-binary-expression": "off"
    }
  },
  {
    files: [
      "src/components/ZentrisSecurityDashboard.tsx",
      "src/components/networking.tsx",
      "src/components/leftnav.tsx",
      "src/app/(dashboard)/hooks/useAuthorized.ts",
      "src/app/login/LoginPage.tsx",
      "src/app/page.tsx"
    ],
    rules: { "unused-imports/no-unused-imports": "error" }
  }
]);
