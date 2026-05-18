'use client'

import { useEffect, useState } from 'react'

type ScanPhase = 'idle' | 'extracting' | 'virustotal' | 'urlhaus' | 'brand' | 'ai' | 'complete'

interface ScanAnimationProps {
  isScanning: boolean
  scanPhase: ScanPhase
}

const phases = [
  { id: 'extracting', label: 'Extracting IOCs', icon: '🎯', duration: 800 },
  { id: 'virustotal', label: 'VirusTotal Lookup', icon: '🔍', duration: 1500 },
  { id: 'urlhaus', label: 'URLhaus Query', icon: '🛡️', duration: 1000 },
  { id: 'brand', label: 'Brand Detection', icon: '🏷️', duration: 800 },
  { id: 'ai', label: 'Threat Verdict Engine', icon: '🧠', duration: 1200 },
  { id: 'complete', label: 'Analysis Complete', icon: '✅', duration: 0 },
]

const terminalLines = [
  '> Initializing threat analysis...',
  '> Parsing input for indicators of compromise...',
  '> Extracting URLs, domains, and IP addresses...',
  '> Querying VirusTotal API...',
  '> Cross-referencing with URLhaus database...',
'  '> Running brand impersonation detection...',
  '> Analyzing patterns with threat engine...',
  '> Generating threat assessment report...',
]

export default function ScanAnimation({ isScanning, scanPhase }: ScanAnimationProps) {
  const [currentLine, setCurrentLine] = useState(0)
  const [visibleLines, setVisibleLines] = useState<string[]>([])
  const [scanProgress, setScanProgress] = useState(0)

  useEffect(() => {
    if (!isScanning) {
      setCurrentLine(0)
      setVisibleLines([])
      setScanProgress(0)
      return
    }

    const interval = setInterval(() => {
      if (currentLine < terminalLines.length) {
        setVisibleLines(prev => [...prev, terminalLines[currentLine]])
        setCurrentLine(prev => prev + 1)
        setScanProgress(Math.min(((currentLine + 1) / terminalLines.length) * 100, 95))
      }
    }, 400)

    return () => clearInterval(interval)
  }, [isScanning, currentLine])

  useEffect(() => {
    if (scanPhase === 'complete') {
      setScanProgress(100)
      setVisibleLines([...visibleLines, '> Threat report generated successfully.'])
    }
  }, [scanPhase])

  if (!isScanning && visibleLines.length === 0) return null

  return (
    <div className="relative">
      {/* Animated scan line effect */}
      {isScanning && (
        <div className="absolute inset-0 overflow-hidden rounded-xl">
          <div 
            className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-[#00ff88] to-transparent animate-scan"
            style={{
              animation: 'scan-line 2s ease-in-out infinite',
              top: '0'
            }}
          />
        </div>
      )}

      <div className="bg-[#0a0a0f] rounded-xl border border-[#1a1a2e] overflow-hidden">
        {/* Header */}
        <div className="bg-[#111119] px-4 py-3 border-b border-[#1a1a2e] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff3366]" />
              <div className="w-3 h-3 rounded-full bg-[#ffcc00]" />
              <div className="w-3 h-3 rounded-full bg-[#00ff88]" />
            </div>
            <span className="text-xs text-gray-400 ml-2">phishguard://scan terminal</span>
          </div>
          
          {isScanning && (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="text-xs text-[#00ff88]">LIVE SCAN</span>
            </div>
          )}
        </div>

        {/* Terminal content */}
        <div className="p-4 h-64 overflow-y-auto font-mono text-sm">
          {visibleLines.map((line, i) => (
            <div 
              key={i} 
              className="text-gray-300 opacity-0 animate-fade-in"
              style={{ animationDelay: `${i * 50}ms`, animationFillMode: 'forwards', animation: 'fade-in 0.3s ease-out forwards' }}
            >
              {line}
            </div>
          ))}
          
          {isScanning && (
            <div className="flex items-center gap-1 text-[#00ff88]">
              <span className="animate-blink">█</span>
            </div>
          )}
        </div>

        {/* Progress bar */}
        <div className="h-1 bg-[#1a1a2e]">
          <div 
            className="h-full bg-gradient-to-r from-[#00ff88] to-[#00ccff] transition-all duration-500 ease-out"
            style={{ width: `${scanProgress}%` }}
          />
        </div>

        {/* Phase indicator */}
        <div className="bg-[#111119] px-4 py-2 border-t border-[#1a1a2e] flex items-center justify-between">
          <div className="flex items-center gap-2">
            {phases.map((phase, i) => (
              <div 
                key={phase.id}
                className={`flex items-center gap-1 px-2 py-1 rounded text-xs ${
                  phases.findIndex(p => p.id === scanPhase) >= i 
                    ? 'bg-[#00ff88]/20 text-[#00ff88]' 
                    : 'bg-[#1a1a2e] text-gray-500'
                }`}
              >
                <span>{phase.icon}</span>
                <span>{phase.label}</span>
              </div>
            ))}
          </div>
          
          <span className="text-xs text-gray-400">{Math.round(scanProgress)}%</span>
        </div>
      </div>

      <style jsx>{`
        @keyframes fade-in {
          from { opacity: 0; transform: translateY(5px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes scan-line {
          0% { top: 0; opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
        .animate-fade-in {
          animation: fade-in 0.3s ease-out forwards;
        }
        .animate-scan {
          animation: scan-line 2s ease-in-out infinite;
        }
        .animate-blink {
          animation: blink 1s step-end infinite;
        }
        @keyframes blink {
          50% { opacity: 0; }
        }
      `}</style>
    </div>
  )
}