'use client'

import { useState } from 'react'

export default function UrlSanitizer() {
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<'defang' | 'refang'>('defang')
  const [output, setOutput] = useState('')
  const [copied, setCopied] = useState(false)

  const defang = (text: string): string => {
    return text
      // URLs with scheme
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/ftp:\/\//gi, 'fxp://')
      // Dots
      .replace(/\./g, '[.]')
      // @ symbols
      .replace(/@/g, '[@]')
      // Protocol slashes already handled above, catch remaining
      .replace(/\/\//g, '/\/')
  }

  const refang = (text: string): string => {
    return text
      .replace(/hxxps:/gi, 'https:')
      .replace(/hxxp:/gi, 'http:')
      .replace(/fxp:/gi, 'ftp:')
      .replace(/\[\.\]/g, '.')
      .replace(/\[@\]/g, '@')
      .replace(/\\\/\//g, '//')
  }

  const process = () => {
    if (!input.trim()) return
    const result = mode === 'defang' ? defang(input) : refang(input)
    setOutput(result)
    setCopied(false)
  }

  const copy = async () => {
    if (!output) return
    await navigator.clipboard.writeText(output)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const swap = () => {
    if (!output) return
    setInput(output)
    setOutput('')
    setMode(mode === 'defang' ? 'refang' : 'defang')
  }

  return (
    <div className="space-y-4">
      {/* Mode toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('defang')}
          className={`flex-1 py-2.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${
            mode === 'defang'
              ? 'bg-[#00ff88] text-black'
              : 'bg-[#111119] text-gray-400 border border-[#1a1a2e] hover:text-white'
          }`}
        >
          Defang
        </button>
        <button
          onClick={() => setMode('refang')
          }
          className={`flex-1 py-2.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${
            mode === 'refang'
              ? 'bg-[#00ff88] text-black'
              : 'bg-[#111119] text-gray-400 border border-[#1a1a2e] hover:text-white'
          }`}
        >
          Refang
        </button>
      </div>

      {/* Input */}
      <div>
        <label className="text-xs text-gray-400 uppercase tracking-wide mb-1 block">
          {mode === 'defang' ? 'Raw URL / IOC' : 'Defanged URL / IOC'}
        </label>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={mode === 'defang'
            ? 'https://www.google.com/path\nor user@domain.com\nor 192.168.1.1'
            : 'hxxps://www[.]google[.]com/path\nor user[@]domain[.]com'
          }
          rows={5}
          className="w-full bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 font-mono text-sm resize-y"
        />
      </div>

      {/* Action buttons */}
      <div className="flex gap-2">
        <button
          onClick={process}
          disabled={!input.trim()}
          className="flex-1 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm disabled:opacity-50"
        >
          {mode === 'defang' ? '⚡ Defang' : '🔄 Refang'}
        </button>
        {output && (
          <button
            onClick={swap}
            className="px-4 py-3 rounded-lg bg-[#111119] border border-[#1a1a2e] text-gray-400 hover:text-white text-sm"
            title="Swap output to input and switch mode"
          >
            ⇅
          </button>
        )}
      </div>

      {/* Output */}
      {output && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-400 uppercase tracking-wide">
              {mode === 'defang' ? 'Defanged Output' : 'Refanged Output'}
            </label>
            <button
              onClick={copy}
              className={`text-xs px-2 py-1 rounded transition-colors ${
                copied
                  ? 'text-[#00ff88] bg-[#00ff88]/10'
                  : 'text-gray-400 hover:text-white bg-[#1a1a2e]'
              }`}
            >
              {copied ? '✓ Copied' : '📋 Copy'}
            </button>
          </div>
          <pre className="w-full bg-[#0a0a0f] border border-[#00ff88]/30 rounded-lg px-4 py-3 text-[#00ff88] font-mono text-sm whitespace-pre-wrap break-all min-h-[60px]">
            {output}
          </pre>
        </div>
      )}

      {/* Info panel */}
      <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-3 text-xs text-gray-400">
        <p className="mb-1"><span className="text-[#00ff88] font-bold">DEFANG</span> — Makes URLs/IOCs safe for sharing in reports, tickets, chat. Replaces <span className="font-mono text-white">.</span> → <span className="font-mono text-white">[.]</span>, <span className="font-mono text-white">http</span> → <span className="font-mono text-white">hxxp</span>, <span className="font-mono text-white">@</span> → <span className="font-mono text-white">[@]</span></p>
        <p><span className="text-[#00ccff] font-bold">REFANG</span> — Reverses defanging to restore original URL/IOC for analysis</p>
      </div>
    </div>
  )
}