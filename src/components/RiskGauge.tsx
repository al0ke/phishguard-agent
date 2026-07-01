'use client'

import { memo } from 'react'

interface RiskGaugeProps {
  score: number
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe'
}

function RiskGauge({ score, threatLevel }: RiskGaugeProps) {
  const getColor = () => {
    switch (threatLevel) {
      case 'critical': return '#ff3366'
      case 'high': return '#ff6633'
      case 'medium': return '#ffcc00'
      case 'low': return '#00ccff'
      case 'safe': return '#00ff88'
      default: return '#00ff88'
    }
  }

  const color = getColor()
  const circumference = 2 * Math.PI * 80
  const strokeDashoffset = circumference - (score / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        {/* Background circle */}
        <svg className="w-full h-full transform -rotate-90">
          <circle
            cx="96"
            cy="96"
            r="80"
            fill="none"
            stroke="#1a1a2e"
            strokeWidth="12"
          />
          {/* Progress circle */}
          <circle
            cx="96"
            cy="96"
            r="80"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{
              filter: `drop-shadow(0 0 10px ${color})`,
              transition: 'stroke-dashoffset 1s ease-out'
            }}
          />
        </svg>
        
        {/* Score display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span 
            className="text-5xl font-bold"
            style={{ color, textShadow: `0 0 20px ${color}` }}
          >
            {score}
          </span>
          <span className="text-sm text-gray-400 mt-1">RISK SCORE</span>
        </div>
      </div>

      {/* Threat level badge */}
      <div 
        className="mt-4 px-6 py-2 rounded-full text-sm font-bold uppercase tracking-wider"
        style={{ 
          backgroundColor: `${color}20`,
          color,
          border: `1px solid ${color}50`
        }}
      >
        {threatLevel === 'critical' ? '⚠️ CRITICAL' : 
         threatLevel === 'high' ? '🔴 HIGH RISK' :
         threatLevel === 'medium' ? '🟡 MEDIUM' :
         threatLevel === 'low' ? '🔵 LOW' : '✅ SAFE'}
      </div>

      {/* Risk breakdown */}
      <div className="mt-6 w-full grid grid-cols-4 gap-2">
        {[
          { label: 'Critical', max: 20, color: '#ff3366' },
          { label: 'High', max: 40, color: '#ff6633' },
          { label: 'Med', max: 60, color: '#ffcc00' },
          { label: 'Low', max: 100, color: '#00ff88' },
        ].map((range) => (
          <div key={range.label} className="text-center">
            <div 
              className="h-2 rounded-full overflow-hidden bg-[#1a1a2e]"
            >
              <div 
                className="h-full rounded-full transition-all duration-1000"
                style={{ 
                  width: `${score >= range.max ? 100 : score > range.max - 20 ? ((score - (range.max - 20)) / 20) * 100 : 0}%`,
                  backgroundColor: range.color,
                  boxShadow: `0 0 10px ${range.color}`
                }}
              />
            </div>
            <span className="text-xs text-gray-500 mt-1 block">{range.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default memo(RiskGauge)