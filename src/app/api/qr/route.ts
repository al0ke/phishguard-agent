import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { image } = await request.json()

    if (!image || typeof image !== 'string') {
      return NextResponse.json({ error: 'Image data required' }, { status: 400 })
    }

    // Extract base64 data from data URL
    const base64Match = image.match(/^data:image\/\w+;base64,(.+)$/)
    if (!base64Match) {
      return NextResponse.json({ error: 'Invalid image format' }, { status: 400 })
    }

    const base64Data = base64Match[1]
    const buffer = Buffer.from(base64Data, 'base64')

    // Use jsQR for decoding — check if available, otherwise return error
    // We'll try to decode using a simple approach
    // Since we can't run native QR libs server-side easily, we'll use the
    // quirc library via a fetch to a free API or process client-side

    // For now, return a message that QR decoding should be done client-side
    // and the client should send the decoded URL instead
    return NextResponse.json({
      error: 'Server-side QR decoding requires additional setup',
      hint: 'QR decoding is handled client-side in the browser',
      image_size: buffer.length,
    })
  } catch (err) {
    console.error('QR route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}