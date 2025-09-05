# Contributing

Thanks for your interest in improving OSS Sentinel!

- Use pnpm and Node 18+.
- Run `pnpm install` at the root; build with `pnpm -r build`.
- API: `pnpm --filter @oss-sentinel/api dev` (set `DEMO=1` for seeds).
- Web: `pnpm --filter @oss-sentinel/web dev`.

Before opening a PR:
- Ensure `pnpm test:ci` passes.
- Include a concise description and screenshots for UI changes.
- Keep changes minimal and focused.

We use the MIT license.
