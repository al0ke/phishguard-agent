import { NextRequest, NextResponse } from 'next/server'
import jsqr from 'jsqr'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { imageData, width, height } = body

    if (!imageData || !width || !height) {
      return NextResponse.json(
        { error: 'Image data, width, and height are required' },
        { status: 400 }
      )
    }

    const data = new Uint8ClampedArray(imageData)
    
    const code = jsqr(data, width, height, {
      inversionAttempts: 'dontInvert'
    })
    
    if (!code) {
      return NextResponse.json(
        { error: 'No QR code found in image' },
        { status: 404 }
      )
    }
    
    return NextResponse.json({
      data: code.data,
      format: 'QR_CODE',
      version: null,
      location: {
        topLeftCorner: code.location.topLeftCorner,
        topRightCorner: code.location.topRightCorner,
        bottomLeftCorner: code.location.bottomLeftCorner
      }
    })
  } catch (error) {
    console.error('QR analysis error:', error)
    return NextResponse.json(
      { error: 'Failed to analyze QR code' },
      { status: 500 }
    )
  }
}
