import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The `test:frontend` suite runs under `node --test --experimental-strip-types`,
// which cannot import a `.tsx` file at all (ERR_UNKNOWN_FILE_EXTENSION). That is
// why those tests assert on component source text rather than rendered output,
// and why no component in this app had ever actually been rendered by a test.
//
// This config exists solely to close that gap. It reuses the app's React plugin
// for the JSX transform and is scoped to `tests/component/**` so the existing
// node:test suites keep running exactly as before.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["tests/component/**/*.test.tsx"],
    restoreMocks: true,
  },
});
