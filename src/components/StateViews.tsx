'use client'

import { memo } from 'react'

interface LoadingStateProps {
  message?: string
}

/** Shared loading indicator used across analyzer tabs for visual consistency. */
export const LoadingState = memo(function LoadingState({ message = 'Processing...' }: LoadingStateProps) {
  return (
    <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-6 text-center">
      <div className="inline-block w-6 h-6 border-2 border-[#00ff88] border-t-transparent rounded-full animate-spin mb-2" />
      <p className="text-sm text-gray-400">{message}</p>
    </div>
  )
})

interface ErrorStateProps {
  message: string
}

/** Shared error banner using the app's neon-red theme color. */
export const ErrorState = memo(function ErrorState({ message }: ErrorStateProps) {
  return (
    <div className="bg-[#ff3366]/10 border border-[#ff3366]/50 rounded-lg p-4">
      <p className="text-[#ff3366] text-sm">{message}</p>
    </div>
  )
})

interface EmptyStateProps {
  icon?: string
  title: string
  description?: string
}

/** Shared empty/idle state shown before a tab has any results. */
export const EmptyState = memo(function EmptyState({ icon = '🛰', title, description }: EmptyStateProps) {
  return (
    <div className="bg-[#111119] border border-[#1a1a2e] rounded-lg p-8 text-center">
      <span className="text-3xl">{icon}</span>
      <p className="text-sm text-gray-300 font-bold mt-2">{title}</p>
      {description && <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">{description}</p>}
    </div>
  )
})
