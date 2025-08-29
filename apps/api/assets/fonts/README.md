Place WOFF2 font files here to embed them in the HTML report for deterministic PDF rendering.

Expected filenames:

- Inter-Regular.woff2
- Inter-Bold.woff2

Any other filenames are ignored by default. You can change the filenames in `apps/api/src/server.ts` where the report HTML is built.

Note: If these files are not present, the report falls back to the system font stack.
