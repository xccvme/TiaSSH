const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
test('portal uses external scripts/styles compatible with strict CSP and safe text rendering',()=>{
 const root=path.join(__dirname,'../web/portal');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
 assert.doesNotMatch(html,/<style>|<script>| style=| onclick=/);
 assert.match(html,/src="\/web\/portal.js"/);
 const script=fs.readFileSync(path.join(root,'portal.js'),'utf8');assert.doesNotMatch(script,/innerHTML|localStorage|sessionStorage/);assert.match(script,/textContent/);
 assert.match(script,/requiresTotpEnrollment/);assert.match(script,/api\/web\/me/);assert.match(script,/btnConfirmReset/);
});
