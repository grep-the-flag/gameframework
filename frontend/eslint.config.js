import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";
import { globalIgnores } from "eslint/config";
import i18next from "eslint-plugin-i18next";

export default tseslint.config(
  globalIgnores(["dist", "coverage", "src/components/ui/**"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat["recommended-latest"],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/components/ui/**", "**/*.test.tsx"],
    plugins: { i18next },
    rules: { "i18next/no-literal-string": ["error", { mode: "jsx-text-only" }] },
  },
);
