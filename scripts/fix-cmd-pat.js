// scripts/fix-cmd-pat.js — patches CMD_PAT in eventAnalyzer.js
const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/detector/eventAnalyzer.js');
let src = fs.readFileSync(file, 'utf8');

// Replace the CMD_PAT block (lines 37-43)
const OLD = /const _CMD_CMDS[\s\S]*?'im'\s*\);/;
const NEW = `const _CMD_CMDS = 'ls|id|cat|wget|curl|whoami|uname|pwd|echo|bash|sh|python3?|perl|ruby|nc|netcat|ncat|ping|nslookup|dig|env|printenv|ifconfig|ipconfig|type';
const CMD_PAT = new RegExp(
  // (A) Shell metachar before command
  \`([;&|\\\`]|\\\\$\\\\()\\\\s*(\${_CMD_CMDS})(\\\\s|;|\\\\)|$)\` +
  // (B) Param/body injection: ?cmd=ls  &command=whoami  exec=bash (? added to prefix set)
  \`|(?:^|[\\\\s&;|=?])(cmd|command|exec|execute|run|shell|system|passthru|popen|proc_open)\\\\s*=\\\\s*(\${_CMD_CMDS})\` +
  // (C) Boolean chaining
  \`|(\\\\|\\\\||&&)\\\\s*(\${_CMD_CMDS})\`,
  'im'
);`;

if (!OLD.test(src)) { console.error('Pattern not found!'); process.exit(1); }
src = src.replace(OLD, NEW);
fs.writeFileSync(file, src, 'utf8');
console.log('CMD_PAT patched successfully.');
