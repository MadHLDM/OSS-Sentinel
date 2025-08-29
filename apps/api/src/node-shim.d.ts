declare module 'node:fs' { const x: any; export = x }
declare module 'node:path' { const x: any; export = x }
declare module 'node:url' { export const fileURLToPath: any }
declare var process: any
interface ImportMeta { url: string }
