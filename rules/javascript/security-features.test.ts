import { createCipheriv, createHash, createHmac, generateKeyPairSync, publicEncrypt, constants } from 'node:crypto';
import https from 'node:https';

declare const key: Buffer;
declare const iv: Buffer;
declare const pub: string;
declare const data: Buffer;
declare const sid: string;
declare const password: string;
declare const username: string;
declare const token: string;
declare const session: { accessToken: string };
declare const res: { cookie(...args: unknown[]): void; setHeader(name: string, value: string): void };

// ruleid: fortify.password-management-hardcoded-password
const clientSecret = 'hunter2-hunter2';
// ruleid: fortify.password-management-hardcoded-password
const settings = { url: 'https://idp.example', clientSecret: 'S3cr3t!S3cr3t!' };
// ok: fortify.password-management-hardcoded-password
const scheme = { token: 'bearer' };
// ok: fortify.password-management-hardcoded-password
const fromEnv = { clientSecret: process.env.CLIENT_SECRET };
// ok: fortify.password-management-hardcoded-password
const tokenKind = 'session-token';
// ok: fortify.password-management-hardcoded-password
const tokenHeader = 'x-session-token';

// ruleid: fortify.password-management-empty-password
const empty = { url: '', clientId: '', clientSecret: '' };

// ruleid: fortify.password-management-password-in-url
const dsn = 'postgres://app:pa55word@db.internal:5432/app';
// ok: fortify.password-management-password-in-url
const plain = 'https://db.internal:5432/app';

// ruleid: fortify.key-management-hardcoded-encryption-key
createCipheriv('aes-256-gcm', Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'), iv);
// ok: fortify.key-management-hardcoded-encryption-key
createCipheriv('aes-256-gcm', key, iv);
// ruleid: fortify.key-management-hardcoded-encryption-key
createHmac('sha256', 'static-hmac-secret');

// ruleid: fortify.key-management-hardcoded-private-key
const pem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`;
// ok: fortify.key-management-hardcoded-private-key
const pemHeader = /^-----BEGIN PRIVATE KEY-----\n/;

// ruleid: fortify.insecure-randomness
const id = Math.floor(Math.random() * 1000);
// ok: fortify.insecure-randomness
const good = crypto.getRandomValues(new Uint32Array(1))[0];

// ruleid: fortify.weak-cryptographic-hash
createHash('md5').update('x').digest('hex');
// ruleid: fortify.weak-cryptographic-hash
createHash('sha1');
// ok: fortify.weak-cryptographic-hash
createHash('sha256');

// ruleid: fortify.weak-encryption
createCipheriv('des-ede3-cbc', key, iv);
// ruleid: fortify.weak-encryption-insecure-mode-of-operation
createCipheriv('aes-128-ecb', key, null);
// ok: fortify.weak-encryption
createCipheriv('aes-256-gcm', key, iv);

// ruleid: fortify.weak-encryption-insufficient-key-size
generateKeyPairSync('rsa', { modulusLength: 1024 });
// ok: fortify.weak-encryption-insufficient-key-size
generateKeyPairSync('rsa', { modulusLength: 2048 });

// ruleid: fortify.weak-encryption-inadequate-rsa-padding
publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_PADDING }, data);
// ok: fortify.weak-encryption-inadequate-rsa-padding
publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);

// ruleid: fortify.insecure-ssl-server-identity-verification-disabled
https.get('https://x.example', { rejectUnauthorized: false });
// ruleid: fortify.insecure-ssl-server-identity-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
// ok: fortify.insecure-ssl-server-identity-verification-disabled
https.get('https://x.example', { rejectUnauthorized: true });

// ruleid: fortify.insecure-transport
const api = 'http://10.0.0.5:8090/api';
// ok: fortify.insecure-transport
const local = 'http://127.0.0.1:8788';
// ok: fortify.insecure-transport
const base = new URL('/x', 'http://hub.invalid');
// ok: fortify.insecure-transport
const secure = 'https://portal.example.com';

// ruleid: fortify.cookie-security-httponly-not-set
res.cookie('sid', sid, { secure: true, sameSite: 'lax' });
// ruleid: fortify.cookie-security-cookie-not-sent-over-ssl
res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
// ok: fortify.cookie-security-httponly-not-set
res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });
// ruleid: fortify.cookie-security-httponly-not-set
res.setHeader('Set-Cookie', 'sid=abc; Path=/; Secure');
// ruleid: fortify.cookie-security-cookie-not-sent-over-ssl
res.setHeader('Set-Cookie', 'sid=abc; Path=/; HttpOnly');
// ok: fortify.cookie-security-cookie-not-sent-over-ssl
res.setHeader('Set-Cookie', 'sid=abc; Path=/; HttpOnly; Secure');

// ruleid: fortify.privacy-violation
console.log('signed in with', password);
// ruleid: fortify.privacy-violation
console.debug('session', session.accessToken);
// ok: fortify.privacy-violation
console.log('signed in as', username);
// ruleid: fortify.privacy-violation
localStorage.setItem('accessToken', token);
// ok: fortify.privacy-violation
localStorage.setItem('theme', 'dark');
