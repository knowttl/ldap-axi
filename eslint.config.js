import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules/**", "dist/**", "build/**", "vendor/**", "prebuilds/**", ".tmp/**", "coverage/**"] },
  js.configs.recommended,
  { files: ["**/*.ts"], extends: [tseslint.configs.recommended] },
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    languageOptions: { globals: globals.node },
  },
  {
    files: ["**/*.ts"],
    rules: { "@typescript-eslint/no-unused-vars": ["error", { ignoreRestSiblings: true }] },
  },
);
