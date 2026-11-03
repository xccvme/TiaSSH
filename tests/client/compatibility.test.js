const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const acorn = require('../../tools/node_modules/acorn');
const root = path.resolve(__dirname, '../..');
test('bundled terminal libraries parse on Android 10 Chromium 74', () => {
  for (const name of ['xterm.js', 'xterm-addon-fit.js']) {
    const source = fs.readFileSync(path.join(root, 'web/vendor', name), 'utf8');
    assert.doesNotThrow(() => acorn.parse(source, {ecmaVersion: 2019}), name);
  }
});
