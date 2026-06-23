import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const authHeader = request.headers.get('authorization')

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return new NextResponse('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="ThreatAnalyzer"' },
    })
  }

  const submitted = authHeader.slice(6)
  // btoa('blueteam101x9:blpw999x$blu') = Ymx1ZXRlYW0xMDF4OTpibHB3OTk5eCRibHU=
  const valid = 'Ymx1ZXRlYW0xMDF4OTpibHB3OTk5eCRibHU='

  if (submitted !== valid) {
    return new NextResponse('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="ThreatAnalyzer"' },
    })
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
}
