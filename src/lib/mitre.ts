// MITRE ATT&CK technique mapping for ThreatAnalyzer
// Static lookup — no external API needed

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  url: string
}

const MITRE_LOOKUP: Record<string, MitreTechnique[]> = {
  phishing: [
    { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566' },
    { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/001' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/002' },
  ],
  malicious_url: [
    { id: 'T1204', name: 'User Execution', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1204' },
    { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1204/002' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/002' },
  ],
  brand_impersonation: [
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/002' },
    { id: 'T1584', name: 'Compromise Infrastructure', tactic: 'Resource Development', url: 'https://attack.mitre.org/techniques/T1584' },
    { id: 'T1583.001', name: 'Domains', tactic: 'Resource Development', url: 'https://attack.mitre.org/techniques/T1583/001' },
  ],
  credential_harvesting: [
    { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1552' },
    { id: 'T1185', name: 'Browser Session Hijacking', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1185' },
  ],
  malware_delivery: [
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', url: 'https://attack.mitre.org/techniques/T1105' },
    { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', url: 'https://attack.mitre.org/techniques/T1071' },
  ],
  malicious_hash: [
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', url: 'https://attack.mitre.org/techniques/T1105' },
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', url: 'https://attack.mitre.org/techniques/T1027' },
  ],
  suspicious_redirect: [
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', url: 'https://attack.mitre.org/techniques/T1027' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/002' },
  ],
  open_ports: [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1190' },
    { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', url: 'https://attack.mitre.org/techniques/T1046' },
  ],
  quishing: [
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1566/002' },
    { id: 'T1204', name: 'User Execution', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1204' },
  ],
}

export function getMitreTags(threatLevel: string, tool: string, findings: string[]): MitreTechnique[] {
  const tags: MitreTechnique[] = []
  const seen = new Set<string>()

  const addTags = (key: string) => {
    const techniques = MITRE_LOOKUP[key]
    if (techniques) {
      for (const t of techniques) {
        if (!seen.has(t.id)) {
          seen.add(t.id)
          tags.push(t)
        }
      }
    }
  }

  // Only tag if suspicious or worse
  if (threatLevel === 'low' || threatLevel === 'clean' || threatLevel === 'unknown') return []

  // Check tool type
  if (tool === 'EMAIL' || tool === 'URL') {
    addTags('phishing')
    addTags('malicious_url')
  }
  if (tool === 'HASH') addTags('malicious_hash')
  if (tool === 'IP') addTags('open_ports')
  if (tool === 'REDIRECT') addTags('suspicious_redirect')
  if (tool === 'QR') addTags('quishing')

  // Check findings text
  const findingsText = findings.join(' ').toLowerCase()
  if (findingsText.includes('brand') || findingsText.includes('impersonation')) addTags('brand_impersonation')
  if (findingsText.includes('credential') || findingsText.includes('login') || findingsText.includes('password')) addTags('credential_harvesting')
  if (findingsText.includes('malware') || findingsText.includes('payload')) addTags('malware_delivery')
  if (findingsText.includes('redirect')) addTags('suspicious_redirect')

  return tags.slice(0, 5)
}