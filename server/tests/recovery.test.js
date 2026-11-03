const test=require('node:test');
const assert=require('node:assert/strict');
const {DatabaseSync}=require('node:sqlite');
const sec=require('../account-security');
function fixture(){const db=new DatabaseSync(':memory:');db.exec(`CREATE TABLE users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,pass_hash TEXT,salt TEXT);CREATE TABLE sessions(token TEXT PRIMARY KEY,user_id INTEGER,created_at TEXT);CREATE TABLE sync_items(user_id INTEGER,value_enc BLOB);`);sec.migrate(db);return db;}
test('recovery verifier is hash-only, one-time initialization, resets auth not ciphertext',()=>{
 const db=fixture(); const key='test-only-not-real-recovery-key-1234567890';
 assert.equal(typeof sec.initializeRecoveryKey,'function');
 sec.initializeRecoveryKey(db,key);
 assert.notEqual(db.prepare('SELECT key_hash FROM recovery_keys').get().key_hash,key);
 assert.throws(()=>sec.initializeRecoveryKey(db,key));
 db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?,?)').run(1,'recovery@example.test','old-hash','unchanged',sec.base32(Buffer.alloc(20,1)),4,1,'Name');
 db.prepare('INSERT INTO sync_items VALUES(?,?)').run(1,Buffer.from('opaque-ciphertext'));
 const token=sec.issueSession(db,1,'client');
 const web=sec.issueSession(db,1,'web');
 db.prepare('INSERT INTO enrollments(challenge_hash,user_id,email,pass_hash,salt,secret,expires_at) VALUES(?,?,?,?,?,?,?)').run('pending',1,'recovery@example.test','h','unchanged','secret',Date.now()+60000);
 const before=db.prepare('SELECT * FROM users').get();
 assert.throws(()=>sec.adminResetByEmail(db,{recoveryKey:'wrong',email:'recovery@example.test',newPassword:'Reset-test-password-123!'}));
 sec.adminResetByEmail(db,{recoveryKey:key,email:'recovery@example.test',newPassword:'Reset-test-password-123!'});
 const u=db.prepare('SELECT * FROM users').get();assert.equal(u.salt,'unchanged');assert.equal(u.totp_secret,null);assert.equal(u.auth_revision,2);assert.equal(sec.lookupSession(db,token,'client'),null);assert.equal(sec.lookupSession(db,web,'web'),null);
 assert.equal(Buffer.from(db.prepare('SELECT value_enc FROM sync_items').get().value_enc).toString(),'opaque-ciphertext');
 assert.ok(require('bcryptjs').compareSync('Reset-test-password-123!',u.pass_hash));
 assert.equal(db.prepare('SELECT count(*) AS n FROM enrollments WHERE user_id=1').get().n,0);
 assert.equal(before.salt,u.salt);
 db.close();
});
test('recovery CLI refuses noninteractive initialization without leaking key',()=>{
 const r=require('node:child_process').spawnSync(process.execPath,['admin-recovery.js','init'],{cwd:require('node:path').join(__dirname,'..'),encoding:'utf8'});
 assert.notEqual(r.status,0);assert.match(r.stderr,/TTY/);assert.doesNotMatch(r.stdout,/[A-Za-z0-9_-]{43}/);
});
