import { NextRequest, NextResponse } from 'next/server'
import { getSupabase } from '@/lib/supabase'

export async function POST(request: NextRequest) {
  try {
    const { action, entry } = await request.json()

    if (action === 'add' && entry) {
      const supabase = getSupabase()
      if (!supabase) {
        return NextResponse.json(
          { error: 'Supabase not configured — set SUPABASE_URL and SUPABASE_SERVICE_KEY' },
          { status: 500 }
        )
      }

      const { data, error } = await (supabase as any)
        .from('phishguard_audit')
        .insert({
          timestamp: new Date().toISOString(),
          tool: entry.tool || 'unknown',
          target: entry.target || '',
          risk_score: entry.riskScore ?? null,
          threat_level: entry.threatLevel ?? 'unknown',
          mitre_tags: entry.mitreTags || [],
          user: entry.user || 'analyst',
        })
        .select()

      if (error) {
        console.error('Supabase insert error:', error.message)
        return NextResponse.json({ error: error.message }, { status: 500 })
      }

      return NextResponse.json({ success: true, entry: data?.[0] })
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
  } catch (err) {
    console.error('Audit log error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const supabase = getSupabase()
    if (!supabase) {
      return NextResponse.json(
        { error: 'Supabase not configured — set SUPABASE_URL and SUPABASE_SERVICE_KEY' },
        { status: 500 }
      )
    }

    const { searchParams } = new URL(request.url)
    const tool = searchParams.get('tool')
    const level = searchParams.get('level')
    const limit = parseInt(searchParams.get('limit') || '100', 10)

    let query = (supabase as any)
      .from('phishguard_audit')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(limit)

    if (tool) query = query.eq('tool', tool)
    if (level) query = query.eq('threat_level', level)

    const { data, error } = await query

    if (error) {
      console.error('Supabase read error:', error.message)
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({
      count: data?.length || 0,
      entries: data || [],
    })
  } catch (err) {
    console.error('Audit log read error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}