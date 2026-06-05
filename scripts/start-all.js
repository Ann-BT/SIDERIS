// scripts/start-all.js
// Sideris 2.0 — Convenience Launcher
//
// Starts ingest, detector, guard, and dashboard servers
// sequentially with staggered delays. Checks all ports are
// free before starting.
// Launch order: ingest → detector → guard → dashboard.

const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const dotenv = require('dotenv');

// Load env before anything else
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const ROOT = path.resolve(__dirname, '..');

const PORTS = [
  { port: parseInt(process.env.INGEST_PORT || '5000', 10), name: 'Ingest' },
  { port: parseInt(process.env.DASHBOARD_PORT || '6001', 10), name: 'Dashboard' },
  { port: parseInt(process.env.PROXY_PORT || '4000', 10), name: 'Proxy' }
];

const servers = [
  {
    name: 'Ingest',
    script: 'src/ingest/server.js',
    label: `Ingest:    http://localhost:${process.env.INGEST_PORT || 5000}/sideris/health`
  },
  {
    name: 'Detector',
    script: 'src/detector/worker.js',
    label: `Detector:  Redis Streams consumer started`
  },
  {
    name: 'Guard',
    script: 'src/guard/guard.js',
    label: `Guard:     Subscribed to sideris:alerts`
  },
  {
    name: 'Proxy',
    script: 'src/proxy/server.js',
    label: `Proxy:     http://localhost:${process.env.PROXY_PORT || 4000} → http://localhost:3000`
  },
  {
    name: 'Storage',
    script: 'src/storage/writer.js',
    label: `Storage:   Redis → PostgreSQL (attack_sessions, attack_events)`
  },
  {
    name: 'Dashboard',
    script: 'src/dashboard/server.js',
    label: `Dashboard: http://localhost:${process.env.DASHBOARD_PORT || 6001}`
  },
  {
    name: 'DashUI',
    cmd: 'npm',
    args: ['run', 'dev'],
    cwd: path.resolve(ROOT, 'src/dashboard/ui'),
    label: `DashUI:    http://localhost:5173  (SOC Dashboard)`,
    noCrashExit: true
  }
];

const children = [];

// PORT CONFLICT CHECK

function checkPort(port) {
  return new Promise((resolve, reject) => {
    const tester = net.createServer();

    tester.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        reject(new Error(`Port ${port} is already in use`));
      } else {
        reject(err);
      }
    });

    tester.once('listening', () => {
      tester.close(() => resolve());
    });

    tester.listen(port, '0.0.0.0');
  });
}

async function checkAllPorts() {
  for (const { port, name } of PORTS) {
    try {
      await checkPort(port);
    } catch {
      // Port in use — try to kill it, then recheck once
      console.warn(`  ⚠ Port ${port} (${name}) is occupied. Attempting to free it...`);
      await new Promise((resolve) => {
        const killer = spawn('npx', ['kill-port', String(port)], {
          cwd: ROOT,
          stdio: 'ignore',
          shell: true
        });
        killer.on('close', resolve);
        setTimeout(resolve, 3000); // safety timeout
      });
      await new Promise((r) => setTimeout(r, 800)); // give OS time to release
      try {
        await checkPort(port);
        console.log(`  ✓ Port ${port} (${name}) freed.`);
      } catch {
        console.error(`  ✗ Port ${port} (${name}) still in use after kill attempt.`);
        console.error(`    Kill manually:  npx kill-port ${port}`);
        process.exit(1);
      }
    }
  }
}

// SERVER LAUNCHER

function startServer(serverDef) {
  return new Promise((resolve) => {
    const cmd  = serverDef.cmd  || 'node';
    const args = serverDef.args || [serverDef.script];
    const cwd  = serverDef.cwd  || ROOT;

    const child = spawn(cmd, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
      shell: !!serverDef.cmd  // npm needs shell on Windows
    });

    children.push(child);

    child.stdout.on('data', (data) => {
      process.stdout.write(`[${serverDef.name}] ${data}`);
    });

    child.stderr.on('data', (data) => {
      process.stderr.write(`[${serverDef.name}] ${data}`);
    });

    child.on('error', (err) => {
      console.error(`[${serverDef.name}] Failed to start: ${err.message}`);
      if (!serverDef.noCrashExit) process.exit(1);
    });

    child.on('exit', (code) => {
      if (code !== null && code !== 0 && !serverDef.noCrashExit) {
        console.error(`\\n[${serverDef.name}] Exited with code ${code}.`);
        console.error(`Shutting down all servers due to ${serverDef.name} crash...`);
        for (const c of children) {
          if (c !== child && !c.killed) c.kill('SIGTERM');
        }
        process.exit(1);
      }
    });

    // Give the server time to start before launching the next one
    const delay = serverDef.cmd ? 2000 : 500; // npm commands need more time
    setTimeout(() => {
      console.log(serverDef.label);
      resolve();
    }, delay);
  });
}

// MAIN

async function main() {
  console.log('\n  ╔═══════════════════════════════════════╗');
  console.log('  ║       SIDERIS 2.0 — Starting...       ║');
  console.log('  ╚═══════════════════════════════════════╝\n');

  // Check all ports are free
  await checkAllPorts();
  console.log('  All ports free ✓\n');

  // Start servers in order with 500ms stagger
  for (const server of servers) {
    await startServer(server);
  }

  console.log('\n  All servers running. Press Ctrl+C to stop.\n');
  console.log('  ┌──────────────────────────────────────────────────────┐');
  console.log(`  │  🌐 Open Juice Shop via proxy:                      │`);
  console.log(`  │     http://localhost:${process.env.PROXY_PORT || 4000}                            │`);
  console.log(`  │                                                      │`);
  console.log(`  │  🖥️  SOC Dashboard:                                  │`);
  console.log(`  │     http://localhost:5173                            │`);
  console.log(`  │                                                      │`);
  console.log(`  │  agent.js is injected automatically — no console    │`);
  console.log(`  │  injection needed.                                   │`);
  console.log(`  │                                                      │`);
  console.log(`  │  🗄️  Events persisted to PostgreSQL automatically      │`);
  console.log('  └──────────────────────────────────────────────────────┘\n');
}

// GRACEFUL SHUTDOWN

process.on('SIGINT', () => {
  console.log('\n  Shutting down all servers...');
  for (const child of children) {
    child.kill('SIGTERM');
  }
  setTimeout(() => process.exit(0), 500);
});

process.on('SIGTERM', () => {
  for (const child of children) {
    child.kill('SIGTERM');
  }
  setTimeout(() => process.exit(0), 500);
});

main().catch((err) => {
  console.error('Start-all failed:', err);
  process.exit(1);
});
