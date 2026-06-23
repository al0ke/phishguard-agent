'use client'

import { useState, useEffect } from 'react'

interface AnalysisInputProps {
  onAnalyze: (input: string) => Promise<void>
  isAnalyzing: boolean
  prefill?: string | null
  onPrefillConsumed?: () => void
}

export default function AnalysisInput({ onAnalyze, isAnalyzing, prefill, onPrefillConsumed }: AnalysisInputProps) {
  const [input, setInput] = useState('')
  const [inputType, setInputType] = useState<'url' | 'email' | 'text'>('url')

  useEffect(() => {
    if (prefill) {
      setInput(prefill)
      setInputType(prefill.startsWith('http') ? 'url' : 'text')
      onPrefillConsumed?.()
    }
  }, [prefill, onPrefillConsumed])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isAnalyzing) return
    await onAnalyze(input)
  }

  return (
    <div className="relative">
      <div className="absolute -inset-0.5 bg-gradient-to-r from-[#00ff88] via-[#00ccff] to-[#ff3366] rounded-xl blur opacity-30 animate-border-glow" />
      
      <form onSubmit={handleSubmit} className="relative bg-[#111119] rounded-xl p-6 border border-[#1a1a2e]">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-[#00ff88]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Threat Analysis Engine</h2>
            <p className="text-sm text-gray-400">Paste URL or email content to analyze</p>
          </div>
        </div>

        <div className="flex gap-2 mb-4">
          {(['url', 'email', 'text'] as const).map((type) => (
            <button
              key={type}
              type="button"
              onClick={() => setInputType(type)}
              className={`px-4 py-2 rounded-lg text-base font-medium transition-all ${
                inputType === type
                  ? 'bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/50'
                  : 'bg-[#1a1a2e] text-gray-400 border border-transparent hover:text-white'
              }`}
            >
              {type === 'url' ? '🔗 URL' : type === 'email' ? '📧 Email' : '📝 Text'}
            </button>
          ))}
        </div>

        <div className="relative">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              inputType === 'url'
                ? 'https://suspicious-domain.com/payload'
                : inputType === 'email'
                ? 'Paste email content here (including headers if available)...'
                : 'Enter any text to analyze for threats...'
            }
            className="w-full h-32 bg-[#0a0a0f] border border-[#1a1a2e] rounded-lg p-4 text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff88]/50 focus:ring-1 focus:ring-[#00ff88]/20 resize-none font-mono text-base"
            disabled={isAnalyzing}
          />
          
          <div className="absolute bottom-2 right-2 text-sm text-gray-500">
            {input.length} chars
          </div>
        </div>

        <button
          type="submit"
          disabled={!input.trim() || isAnalyzing}
          className={`mt-4 w-full py-3.5 rounded-lg font-bold text-base transition-all flex items-center justify-center gap-2 ${
            !input.trim() || isAnalyzing
              ? 'bg-[#1a1a2e] text-gray-500 cursor-not-allowed'
              : 'bg-gradient-to-r from-[#00ff88] to-[#00ccff] text-black hover:shadow-lg hover:shadow-[#00ff88]/20'
          }`}
        >
          {isAnalyzing ? 'Analyzing...' : 'Analyze Threat'}
        </button>
      </form>
    </div>
  )
}
