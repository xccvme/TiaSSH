const test = require('node:test');
const assert = require('node:assert/strict');
test('RFC6238 SHA1 vectors and base32 roundtrip', () => {
  const s = require('../account-security');
  const secret = s.base32(Buffer.from('12345678901234567890'));
  for (const [time, expected] of [[59,'94287082'],[1111111109,'07081804'],[1111111111,'14050471'],[1234567890,'89005924'],[2000000000,'69279037'],[20000000000,'65353130']]) {
    assert.equal(s.totp(secret, Math.floor(time/30), 8), expected);
  }
});

test('OTP counter rejects a previously consumed time step', () => {
  const s = require('../account-security');
  const secret=s.base32(Buffer.alloc(20,4));
  const counter=Math.floor(Date.now()/30000);
  const otp=s.totp(secret,counter);
  assert.equal(s.otpCounter(secret,otp,-1),counter);
  assert.equal(s.otpCounter(secret,otp,counter),null);
});
