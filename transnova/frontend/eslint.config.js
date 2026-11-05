import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Event fields hold raw attacker strings: they must only ever be rendered as text.
      "no-restricted-syntax": ["error", { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
        message: "Never render evidence as HTML." }],
    },
  },
);
