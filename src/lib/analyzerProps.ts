export type InvestigateTab = 'url' | 'domain' | 'hash' | 'ip' | 'redirect' | 'dns' | 'whois' | 'bulk'

export interface AnalyzerShellProps {
  prefill?: string | null
  onPrefillConsumed?: () => void
  onInvestigate?: (tab: InvestigateTab, value: string) => void
}
