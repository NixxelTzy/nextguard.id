/**
 * NextGuard — Tor Exit Node Detector
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

let torExitNodes: Set<string> = new Set()
let loaded = false

function getDataDir(): string {
  try {
    // Works in both CJS (__dirname available) and bundled output
    return join(__dirname, '..', 'data')
  } catch {
    return join(process.cwd(), 'src', 'data')
  }
}

function loadTorList(): void {
  if (loaded) return
  loaded = true
  try {
    const filePath = join(getDataDir(), 'tor-exit-nodes.txt')
    if (!existsSync(filePath)) return
    const content = readFileSync(filePath, 'utf8')
    torExitNodes = new Set(
      content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
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
