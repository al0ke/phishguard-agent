'use client'

interface IOC {
  type: string
  value: string
  source: string
}

interface IOCListProps {
  iocs: {
    ips: string[]
    domains: string[]
    urls: string[]
    hashes: string[]
  }
}

export default function IOCList({ iocs }: IOCListProps) {
  const allIocs: IOC[] = [
    ...iocs.ips.map(ip => ({ type: 'IP', value: ip, source: 'Embedded' })),
    ...iocs.domains.map(d => ({ type: 'Domain', value: d, source: 'Embedded' })),
    ...iocs.urls.map(u => ({ type: 'URL', value: u, source: 'Embedded' })),
    ...iocs.hashes.map(h => ({ type: 'Hash', value: h, source: 'Embedded' })),
  ]

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  if (allIocs.length === 0) {
    return (
      <div className="bg-[#111119] rounded-xl p-6 border border-[#1a1a2e]">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-[#00ccff]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">IOC Extraction</h3>
            <p className="text-sm text-gray-400">No indicators found</p>
          </div>
        </div>
        <div className="text-center py-8 text-gray-500">
          No indicators of compromise detected in this sample
        </div>
      </div>
    )
  }

  const groupedIocs = {
    URL: allIocs.filter(i => i.type === 'URL'),
    Domain: allIocs.filter(i => i.type === 'Domain'),
    IP: allIocs.filter(i => i.type === 'IP'),
    Hash: allIocs.filter(i => i.type === 'Hash'),
  }

  return (
    <div className="bg-[#111119] rounded-xl border border-[#1a1a2e] overflow-hidden">
      <div className="bg-[#1a1a2e] px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-[#00ccff]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">IOC Extraction</h3>
            <p className="text-sm text-gray-400">{allIocs.length} indicators found</p>
          </div>
        </div>
        
        <button
          onClick={() => copyToClipboard(JSON.stringify(iocs, null, 2))}
          className="px-4 py-2 rounded-lg bg-[#00ccff]/10 text-[#00ccff] text-sm font-medium hover:bg-[#00ccff]/20 transition-all flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          Export All
        </button>
      </div>

      <div className="p-4 space-y-4">
        {Object.entries(groupedIocs).map(([type, items]) => (
          items.length > 0 && (
            <div key={type}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                  type === 'URL' ? 'bg-[#00ff88]/20 text-[#00ff88]' :
                  type === 'Domain' ? 'bg-[#ffcc00]/20 text-[#ffcc00]' :
                  type === 'IP' ? 'bg-[#ff3366]/20 text-[#ff3366]' :
                  'bg-[#00ccff]/20 text-[#00ccff]'
                }`}>
                  {type} ({items.length})
                </span>
              </div>
              
              <div className="space-y-2">
                {items.map((ioc, i) => (
                  <div 
                    key={i}
                    className="flex items-center justify-between bg-[#0a0a0f] rounded-lg px-3 py-2 border border-[#1a1a2e] group hover:border-[#00ccff]/30 transition-all"
                  >
                    <code className="text-sm text-gray-300 truncate max-w-md">{ioc.value}</code>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">{ioc.source}</span>
                      <button
                        onClick={() => copyToClipboard(ioc.value)}
                        className="p-1 rounded hover:bg-[#1a1a2e] text-gray-400 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                        title="Copy to clipboard"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )
        ))}
      </div>
    </div>
  )
}