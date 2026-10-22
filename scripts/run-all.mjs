#!/usr/bin/env node
/**
 * NextGuard Universal Orchestrator & Simultaneous Runner
 * Launches both the Python Machine Learning Subsystem and the NextGuard TypeScript Firewall
 * with unified telemetry, health synchronization, and graceful shutdown.
 */

import { spawn } from 'node:child_process'
import http from 'node:http'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const ROOT_DIR = path.resolve(__dirname, '..')
const ML_DIR = path.resolve(ROOT_DIR, 'machine-learning')
const WEB_TEST_DIR = path.resolve(ROOT_DIR, 'web-test')

const ML_PORT = process.env.NEXTGUARD_ML_PORT ? parseInt(process.env.NEXTGUARD_ML_PORT, 10) : 8000
const WAF_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000
const PYTHON_BIN = process.env.PYTHON_BIN || 'python'

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
}

console.log(`\n${C.bold}${C.cyan}======================================================================${C.reset}`)
console.log(`${C.bold}${C.cyan}  🛡️  NextGuard Universal Security Suite — Simultaneous Orchestrator ${C.reset}`)
console.log(`${C.bold}${C.cyan}======================================================================${C.reset}\n`)

let pythonProcess = null
let wafProcess = null
let isShuttingDown = false

function cleanupAndExit(code = 0) {
  if (isShuttingDown) return
  isShuttingDown = true
  console.log(`\n${C.yellow}🛑 Shutting down NextGuard services...${C.reset}`)

  if (pythonProcess) {
    try {
      console.log(`  ${C.gray}Stopping Python ML engine (PID ${pythonProcess.pid})...${C.reset}`)
      pythonProcess.kill('SIGINT')
    } catch {}
    pythonProcess = null
  }

  if (wafProcess) {
    try {
      console.log(`  ${C.gray}Stopping NextGuard Firewall server (PID ${wafProcess.pid})...${C.reset}`)
      wafProcess.kill('SIGINT')
    } catch {}
    wafProcess = null
  }

  setTimeout(() => {
    console.log(`${C.green}✓ All services stopped cleanly.${C.reset}\n`)
    process.exit(code)
  }, 600)
}

process.on('SIGINT', () => cleanupAndExit(0))
process.on('SIGTERM', () => cleanupAndExit(0))
process.on('exit', () => cleanupAndExit(0))

async function checkPortHealthy(port, pathStr = '/health') {
  return new Promise((resolve) => {
    const req = http.get({
      host: '127.0.0.1',
      port,
      path: pathStr,
      timeout: 1000,
    }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 400)
    })
    req.on('error', () => resolve(false))
    req.on('timeout', () => { req.destroy(); resolve(false) })
  })
}

async function startPythonService() {
  const isAlreadyRunning = await checkPortHealthy(ML_PORT)
  if (isAlreadyRunning) {
    console.log(`${C.green}✓ Python ML Service is already active on http://127.0.0.1:${ML_PORT}${C.reset}`)
    return true
  }

  console.log(`${C.cyan}[1/2] Starting Python ML Inference Microservice (FastAPI + Uvicorn)...${C.reset}`)
  
  pythonProcess = spawn(PYTHON_BIN, ['server.py', '--port', String(ML_PORT)], {
    cwd: ML_DIR,
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  pythonProcess.stdout.on('data', (chunk) => {
    const lines = chunk.toString().trim().split('\n')
    for (const line of lines) {
      if (line) console.log(`${C.green}[Python ML]${C.reset} ${line}`)
    }
  })

  pythonProcess.stderr.on('data', (chunk) => {
    const lines = chunk.toString().trim().split('\n')
    for (const line of lines) {
      if (line) console.log(`${C.green}[Python ML]${C.reset} ${line}`)
    }
  })

  pythonProcess.on('exit', (code) => {
    if (!isShuttingDown) {
      console.log(`${C.red}[Python ML] Process exited with code ${code}${C.reset}`)
      cleanupAndExit(code || 1)
    }
  })

  // Poll /health up to 10 seconds
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 500))
    const healthy = await checkPortHealthy(ML_PORT)
    if (healthy) {
      console.log(`${C.green}✓ Python ML Service is ready and healthy on http://127.0.0.1:${ML_PORT}${C.reset}`)
      return true
    }
  }

  console.log(`${C.yellow}⚠ Python ML Service started (initial probe pending). Firewall will connect dynamically.${C.reset}`)
  return true
}

async function startNextGuardWaf() {
  console.log(`\n${C.cyan}[2/2] Starting NextGuard TypeScript Firewall & Interactive Testing Studio...${C.reset}`)

  wafProcess = spawn('node', ['server.mjs'], {
    cwd: WEB_TEST_DIR,
    env: {
      ...process.env,
      PORT: String(WAF_PORT),
      NEXTGUARD_PYTHON_ML_URL: `http://127.0.0.1:${ML_PORT}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  wafProcess.stdout.on('data', (chunk) => {
    const lines = chunk.toString().trim().split('\n')
    for (const line of lines) {
      if (line) console.log(`${C.cyan}[NextGuard WAF]${C.reset} ${line}`)
    }
  })

  wafProcess.stderr.on('data', (chunk) => {
    const lines = chunk.toString().trim().split('\n')
    for (const line of lines) {
      if (line) console.log(`${C.yellow}[NextGuard WAF]${C.reset} ${line}`)
    }
  })

  wafProcess.on('exit', (code) => {
    if (!isShuttingDown) {
      console.log(`${C.red}[NextGuard WAF] Process exited with code ${code}${C.reset}`)
      cleanupAndExit(code || 1)
    }
  })
}

async function main() {
  await startPythonService()
  await startNextGuardWaf()

  console.log(`\n${C.bold}${C.green}🚀 ALL SERVICES RUNNING SIMULTANEOUSLY:${C.reset}`)
  console.log(`  ${C.bold}• Python ML Engine:${C.reset}     http://127.0.0.1:${ML_PORT}`)
  console.log(`  ${C.bold}• Swagger ML API Docs:${C.reset}  http://127.0.0.1:${ML_PORT}/docs`)
  console.log(`  ${C.bold}• NextGuard Target WAF:${C.reset} http://localhost:${WAF_PORT}`)
  console.log(`  ${C.bold}• Attack Studio UI:${C.reset}     http://localhost:${WAF_PORT}/`)
  console.log(`\n${C.gray}Press Ctrl+C to stop all services simultaneously.${C.reset}\n`)
}

main().catch((err) => {
  console.error(`${C.red}Fatal startup error:${C.reset}`, err)
  cleanupAndExit(1)
})
