// scripts/tunnel.js
// Sideris 2.0 — ngrok Tunnel Controller (Direct CLI Edition)

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const PROXY_PORT = parseInt(process.env.PROXY_PORT || '4000', 10);

// Helper to check for global ngrok
function getGlobalNgrokPath() {
  try {
    const pathSeparator = process.platform === 'win32' ? ';' : ':';
    const pathDirs = (process.env.PATH || '').split(pathSeparator);
    
    for (const dir of pathDirs) {
      // Ignore our own project's node_modules or bin paths
      if (dir.includes('node_modules') || dir.includes('.bin')) {
        continue;
      }
      
      const binaryName = process.platform === 'win32' ? 'ngrok.exe' : 'ngrok';
      const fullPath = path.join(dir, binaryName);
      
      if (fs.existsSync(fullPath)) {
        try {
          if (process.platform !== 'win32') {
            fs.accessSync(fullPath, fs.constants.X_OK);
          }
          return fullPath;
        } catch (e) {
          // No execute permission
        }
      }
    }
  } catch (e) {
    // Ignore
  }
  return null;
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  const globalNgrok = getGlobalNgrokPath();

  if (!globalNgrok) {
    console.error('\n  ❌ Error: Global ngrok binary not found in your PATH.');
    console.error('     👉 Please install ngrok globally on your system first:');
    console.error('        • Using yay (AUR):    yay -S ngrok');
    console.error('        • Using paru (AUR):   paru -S ngrok');
    console.error('        • Using Snap:         sudo snap install ngrok\n');
    process.exit(1);
  }

  // Handle authtoken configuration command
  if (command === 'auth') {
    const token = args[1];
    if (!token) {
      console.error('\n  ❌ Error: Missing authtoken.');
      console.error('     Usage: npm run tunnel-auth <your-ngrok-token>\n');
      process.exit(1);
    }

    console.log(`\n  ⚙️  Configuring ngrok authtoken using global installation...`);
    const child = spawn(globalNgrok, ['config', 'add-authtoken', token], { stdio: 'inherit' });
    child.on('close', (code) => {
      if (code === 0) {
        console.log('  ✓ Authtoken configured successfully!\n');
      } else {
        console.error('  ❌ Failed to set authtoken.\n');
      }
      process.exit(code);
    });
    return;
  }

  // Expose the tunnel
  console.log('\n  ┌──────────────────────────────────────────┐');
  console.log('  │    SIDERIS 2.0 — Exposing Tunnel...      │');
  console.log('  └──────────────────────────────────────────┘\n');

  console.log(`  Connecting tunnel to Sideris Proxy on port ${PROXY_PORT} using global ngrok...`);

  // Kill any running ngrok instances first to prevent port collisions or limit errors
  try {
    execSync('killall ngrok 2>/dev/null || pkill ngrok 2>/dev/null || true');
  } catch (e) {}

  // Spawn ngrok process directly
  const ngrokProc = spawn(globalNgrok, ['http', String(PROXY_PORT), '--log=stdout']);

  let tunnelFound = false;

  ngrokProc.stdout.on('data', (data) => {
    const msg = data.toString();
    
    // Parse the tunnel URL
    const match = msg.match(/url=(https:\/\/[^\s]+)/);
    if (match && !tunnelFound) {
      tunnelFound = true;
      const url = match[1];

      console.log('\n  🚀 Tunnel successfully established!');
      
      const lines = [
        '🌐 Test protected website from other devices:',
        `   ${url}`,
        '',
        '🖥️  SOC Dashboard (Monitor alerts and sessions):',
        `   ${url}/dashboard/`,
        '',
        '📊 Local ngrok inspection dashboard (if 4040 is free):',
        '   http://localhost:4040'
      ];
      
      const maxLineLength = Math.max(...lines.map(l => l.length));
      const paddingLength = maxLineLength + 4;
      const border = '─'.repeat(paddingLength);
      
      console.log(`  ┌${border}┐`);
      for (const line of lines) {
        const padSize = paddingLength - line.length;
        const spaces = padSize > 0 ? ' '.repeat(padSize) : '';
        console.log(`  │ ${line}${spaces} │`);
      }
      console.log(`  └${border}┘\n`);
      console.log('  Press Ctrl+C to close the tunnel.\n');
    }

    // Parse errors
    if (msg.includes('err="') || msg.includes('lvl=eror') || msg.includes('lvl=warn')) {
      if (msg.includes('ERR_NGROK_105') || msg.includes('authentication failed') || msg.includes('authtoken')) {
        console.error('\n  ❌ Error: Missing or invalid ngrok authtoken.');
        console.error('     Fix: Run "npm run tunnel-auth <your_token>" to configure it.');
        ngrokProc.kill();
        process.exit(1);
      }
      if (msg.includes('ERR_NGROK_108') || msg.includes('limit') || msg.includes('active tunnel')) {
        console.error('\n  ❌ Error: Too many active tunnels. Free accounts are limited to 1.');
        console.error('     Fix: Make sure you don\'t have ngrok running on another machine/session.');
        ngrokProc.kill();
        process.exit(1);
      }
    }
  });

  ngrokProc.stderr.on('data', (data) => {
    console.error(`[ngrok-error] ${data.toString().trim()}`);
  });

  ngrokProc.on('close', (code) => {
    if (!tunnelFound) {
      console.error(`\n  ❌ ngrok exited early with code ${code}.`);
      console.error('     Check that Sideris is running first ("npm run start-all").\n');
    } else {
      console.log('\n  Tunnel closed.');
    }
    process.exit(code);
  });

  // Handle clean exit
  process.on('SIGINT', () => {
    ngrokProc.kill();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    ngrokProc.kill();
    process.exit(0);
  });
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
