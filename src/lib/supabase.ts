import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.SUPABASE_URL || ''
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || ''

let _client: ReturnType<typeof createClient> | null = null

export function getSupabase() {
  if (!supabaseUrl || !supabaseKey) return null
  if (!_client) {
    _client = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false },
    })
  }
  return _client
}