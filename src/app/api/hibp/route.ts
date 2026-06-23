import { NextRequest, NextResponse } from 'next/server'
import { checkHibpBreaches, checkHibpPassword } from '../../../lib/hibp'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { email, type } = body
    
    if (!email && !type) {
      return NextResponse.json(
        { error: 'Email address or type is required' },
        { status: 400 }
      )
    }
    
    if (type === 'password' && email) {
      const result = await checkHibpPassword(email)
      return NextResponse.json(result)
    }
    
    if (email) {
      const result = await checkHibpBreaches(email)
      if (!result) {
        return NextResponse.json(
          { error: 'Failed to check HIBP database' },
          { status: 500 }
        )
      }
      return NextResponse.json(result)
    }
    
    return NextResponse.json(
      { error: 'Invalid request' },
      { status: 400 }
    )
  } catch (error) {
    console.error('HIBP API error:', error)
    return NextResponse.json(
      { error: 'Failed to check breach database' },
      { status: 500 }
    )
  }
}
