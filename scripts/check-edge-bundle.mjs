import fs from 'node:fs'

const files = ['dist/index.mjs', 'dist/edge.mjs', 'dist/adapters/nextjs.mjs']

for (const file of files) {
  if (!fs.existsSync(file)) {
    console.log(file, '- NOT FOUND')
    continue
  }
  const content = fs.readFileSync(file, 'utf8')
  const issues = []

  // Check for static ESM imports from node: modules
  const staticImports = content.match(/^import\s+.*from\s+['"]node:[^'"]+['"]/gm)
  if (staticImports) issues.push(...staticImports.map(l => '  STATIC: ' + l.slice(0, 80)))

  // Check for require('stream') or require('node:stream') — traceable by webpack
  const requireStream = content.match(/require\(['"](?:node:)?stream['"]\)/g)
  if (requireStream) issues.push(...requireStream.map(l => '  REQUIRE_STREAM: ' + l))

  if (issues.length > 0) {
    console.log('\n' + file + ' - HAS ISSUES:')
    issues.forEach(i => console.log(i))
  } else {
    console.log(file + ' - CLEAN ✓')
  }
}
