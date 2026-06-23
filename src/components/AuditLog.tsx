'use client'

import { useState, useEffect } from 'react'

export default function AuditLog() {
  const [entries, setEntries] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [levelFilter, setLevelFilter] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/audit')
      const data = await res.json()
      setEntries(data.entries || [])
    } catch {
      setEntries([])
    }
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const filtered = entries.filter(e => {
    if (filter && !e.target?.toLowerCase().includes(filter.toLowerCase()) && !e.tool?.toLowerCase().includes(filter.toLowerCase())) return false
    if (levelFilter && e.threatLevel?.toLowerCase() !== levelFilter.toLowerCase()) return false
    return true
  })

  const levelColor = (level: string) => {
    if (level === 'critical' || level === 'high') return 'text-[#ff3366]'
    if (level === 'medium') return 'text-[#ffcc00]'
    if (level === 'low' || level === 'clean') return 'text-[#00ff88]'
    return 'text-gray-500'
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-2">
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Search target or tool..."
          className="flex-1 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm"
        />
        <select
          value={levelFilter}
          onChange={e => setLevelFilter(e.target.value)}
          className="bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-3 py-2.5 text-sm text-gray-400 focus:outline-none"
        >
          <option value="">All levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button onClick={load} className="px-4 py-2.5 rounded-lg bg-[#111119] text-gray-400 border border-[#1a1a2e] hover:text-white text-sm">
          ↻
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-2 text-center">
          <p className="text-xs text-gray-400">Total Scans</p>
          <p className="text-lg font-bold text-white">{entries.length}</p>
        </div>
        <div className="bg-[#ff3366]/10 border border-[#ff3366]/30 rounded-lg p-2 text-center">
          <p className="text-xs text-gray-400">Threats</p>
          <p className="text-lg font-bold text-[#ff3366]">{entries.filter(e => e.threatLevel === 'critical' || e.threatLevel === 'high').length}</p>
        </div>
        <div className="bg-[#00ff88]/10 border border-[#00ff88]/30 rounded-lg p-2 text-center">
          <p className="text-xs text-gray-400">Clean</p>
          <p className="text-lg font-bold text-[#00ff88]">{entries.filter(e => e.threatLevel === 'low' || e.threatLevel === 'clean').length}</p>
        </div>
      </div>

      {/* Log entries */}
      {loading ? (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center text-sm text-gray-400">Loading...</div>
      ) : filtered.length === 0 ? (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
          <span className="text-3xl">📋</span>
          <p className="text-sm text-gray-400 mt-2">{entries.length === 0 ? 'No scans logged yet' : 'No matches for filter'}</p>
        </div>
      ) : (
        <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1a1a2e] text-gray-400 uppercase">
                <th className="text-left px-3 py-2">Time</th>
                <th className="text-left px-2 py-2">Tool</th>
                <th className="text-left px-2 py-2">Target</th>
                <th className="text-center px-2 py-2">Score</th>
                <th className="text-center px-2 py-2">Level</th>
                <th className="text-left px-2 py-2">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e, i) => (
                <tr key={i} className="border-b border-[#1a1a2e] last:border-0">
                  <td className="px-3 py-2 text-gray-500 font-mono whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="px-2 py-2 text-gray-400 font-mono">{e.tool}</td>
                  <td className="px-2 py-2 text-white font-mono break-all max-w-[200px]">{e.target}</td>
                  <td className="px-2 py-2 text-center">
                    {e.riskScore !== null && (
                      <span className={`font-bold ${e.riskScore >= 70 ? 'text-[#ff3366]' : e.riskScore >= 40 ? 'text-[#ffcc00]' : 'text-[#00ff88]'}`}>
                        {e.riskScore}
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-2 text-center">
                    <span className={`text-[10px] font-bold uppercase ${levelColor(e.threatLevel)}`}>{e.threatLevel}</span>
                  </td>
                  <td className="px-2 py-2">
                    {e.mitreTags?.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {e.mitreTags.map((t: string) => (
                          <span key={t} className="text-[9px] font-mono text-[#cc99ff] bg-[#cc99ff]/10 px-1 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-gray-600">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}