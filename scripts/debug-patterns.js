// scripts/debug-patterns.js
'use strict';
const { analyze } = require('../src/detector/eventAnalyzer');

function test(label, endpoint, body) {
  const ev = { source: 'backend', event_type: 'backend_log',
    data: { method: 'GET', endpoint, status: '200', body: body || '', userAgent: 'Mozilla/5.0' }};
  const r = analyze(ev);
  const ok = r.attack_type !== 'normal_browsing';
  console.log(`  ${ok ? '✅' : '❌'} [${r.attack_type.padEnd(20)}] ${label}`);
}

console.log('\n=== CMDi tests ===');
test('cmd=ls in URL',         '/run?cmd=ls%20-la');
test('command=whoami body',   '/exec', 'command=whoami');
test(';id URL',               '/ping?host=127.0.0.1;id');
test('$(whoami) URL',         '/ping?h=$(whoami)');

console.log('\n=== LFI tests ===');
test('php://filter URL',      '/page?file=php://filter/convert.base64-encode/resource=/etc/passwd');
test('phar:// URL',           '/load?f=phar://shell.phar');
test('data:// URL',           '/inc?p=data://text/plain,<?php system($_GET[cmd]);?>');

console.log('\n=== SSTI tests ===');
test('{{7*7}} Jinja2',        '/name?n={{7*7}}');
test('${7*7} Twig',           '/t?x=${7*7}');

console.log('\n=== Normal (should NOT fire) ===');
test('cmd in normal word',    '/command-line-tools/docs');
test('/api/products',         '/api/products');
test('/admin/dashboard',      '/admin/dashboard');
