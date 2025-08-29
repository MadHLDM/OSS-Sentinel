declare module '@prisma/client' {
  export class PrismaClient {
    constructor(...args: any[])
    $connect(): Promise<void>
    $disconnect(): Promise<void>
    project: any
    scan: any
    dependency: any
    vulnerability: any
    license: any
    licenseFinding: any
  }
}

