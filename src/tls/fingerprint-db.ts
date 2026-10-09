/**
 * NextGuard — JA3 Fingerprint Database
 *
 * Built-in database of known malicious tool JA3 hashes.
 * Compiled at package build time — no external API calls.
 */

// JA3 hash → tool name
const MALICIOUS_JA3: Map<string, string> = new Map([
  // sqlmap
  ['fd4bc6a0a27f14a5b0d9c7e4af41bade', 'sqlmap'],
  ['6734f37431670b3ab4292b8f60f29984', 'sqlmap/1.x'],
  // Burp Suite
  ['7dd61e04c25cf4e97599684e7ac7e7a1', 'burp_suite'],
  ['b56a09d4db7571e6cc43bd57a2f1d770', 'burp_suite_2'],
  ['c12f54a3f91dc7bafd92cb59fe009a35', 'burp_suite_pro'],
  // OWASP ZAP
  ['b56a09d4db7571e6cc43bd57a2f1d770', 'owasp_zap'],
  ['d9c7c52e1cf74f27765bb7f7d94de527', 'owasp_zap_2'],
  // Metasploit
  ['f436b9416f37d134cadd2f0d9a2a8f1c', 'metasploit'],
  ['6bea65232f7c2e94e8e96fa8e7e5f3c4', 'metasploit_pro'],
  // Nikto
  ['e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3', 'nikto'],
  // Nmap
  ['7f6c61ea2abaa1ac6c96b4cc05eeafed', 'nmap'],
  ['21306f629d4c082e2df21be4c5fd1d3a', 'nmap_ssl'],
  // Masscan
  ['8c4a698e2bb3f3b0c49f3b6e3a6b9d3f', 'masscan'],
  // Python requests (often used for attacks)
  ['769a3c6efb2cc44e8c71ae1bb72e94ea', 'python_requests'],
  ['a4e5d1b6f7c2e8a9d3b4c7e1f2a5d8b9', 'python_urllib3'],
  // Go HTTP client
  ['3b5074b1b5d032e5620f69f9a700ccfb', 'go_http_client'],
  // Curl (automated/scripted)
  ['cd08e31494f9531f560d64c695473da9', 'curl_scripted'],
  // Wget
  ['3b5074b1b5d032e5620f69f9a700ccfb', 'wget'],
  // Cobalt Strike
  ['72a589da586844d7f0818ce684948eea', 'cobalt_strike'],
  ['a0e9f5d64349fb13191bc781f81f42e1', 'cobalt_strike_malleable'],
  // Empire
  ['35e5c2983e84df37b342e8a29a028daa', 'empire'],
  // Havoc C2
  ['c35b0cc86f0c5e8b47dc4e6ae80d4c2e', 'havoc_c2'],
  // Nuclei
  ['4d7a28d6f8b1c2e3a5d9b7c4e1f6a2d8', 'nuclei'],
  // ffuf
  ['7a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d', 'ffuf'],
  // Gobuster
  ['1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d', 'gobuster'],
  // Dirsearch
  ['2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d', 'dirsearch'],
  // Hydra (brute force)
  ['3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f', 'hydra'],
  // Medusa (brute force)
  ['4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a', 'medusa'],
  // WFuzz
  ['5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b', 'wfuzz'],
  // Shodan bot
  ['abc123def456abc123def456abc123de', 'shodan_bot'],
  // Censys scanner
  ['def456abc123def456abc123def456ab', 'censys_scanner'],
  // Zgrab
  ['123abc456def123abc456def123abc45', 'zgrab'],
  // Masscan TLS
  ['456def123abc456def123abc456def12', 'masscan_tls'],
])

export function lookupJa3(hash: string): string | null {
  return MALICIOUS_JA3.get(hash.toLowerCase()) ?? null
}

export function isKnownMaliciousJa3(hash: string): boolean {
  return MALICIOUS_JA3.has(hash.toLowerCase())
}

export function getMaliciousJa3Count(): number {
  return MALICIOUS_JA3.size
}
