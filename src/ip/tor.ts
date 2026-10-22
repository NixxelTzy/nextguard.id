/**
 * NextGuard — Tor Exit Node Detector
 * Edge Runtime compatible — Node.js fs/path loaded lazily at runtime via new Function.
 */

declare const EdgeRuntime: string | undefined

let torExitNodes: Set<string> = new Set()
let loaded = false

function loadTorList(): void {
  if (loaded) return
  loaded = true
  // Only run in full Node.js — skip Edge Runtime entirely
  const isEdge =
    typeof EdgeRuntime !== 'undefined' ||
    (typeof process !== 'undefined' && process.env?.NEXT_RUNTIME === 'edge')
  if (isEdge) return

  try {
    // Use new Function() so bundlers (webpack/esbuild/edge) cannot trace these requires
    const rq = new Function('m', 'return require(m)') as (m: string) => any
    const fsm = rq('fs') as typeof import('fs')
    const pathm = rq('path') as typeof import('path')

    let dataDir: string
    try {
      dataDir = pathm.join((__dirname as any) ?? '.', '..', 'data')
    } catch {
      dataDir = pathm.join(process.cwd(), 'src', 'data')
    }
    const filePath = pathm.join(dataDir, 'tor-exit-nodes.txt')
    if (!fsm.existsSync(filePath)) return
    const content = fsm.readFileSync(filePath, 'utf8')
    torExitNodes = new Set(
      content.split('\n').map((l: string) => l.trim()).filter((l: string) => l && !l.startsWith('#'))
    )
  } catch {
    torExitNodes = new Set()
  }
}

export function isTorExitNode(ip: string): boolean {
  loadTorList()
  return torExitNodes.has(ip.trim())
}

export function getTorExitNodeCount(): number {
  loadTorList()
  return torExitNodes.size
}
