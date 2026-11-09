import jwt from 'jsonwebtoken';
import https from 'node:https';
import multer from 'multer';
import { createCipheriv, createHmac, pbkdf2Sync, randomBytes, pseudoRandomBytes, scryptSync } from 'node:crypto';

declare const token: string;
declare const secret: string;
declare const password: string;
declare const iv: Buffer;
declare const sid: string;
declare const res: { cookie(...args: unknown[]): void };

// ruleid: fortify.json-web-token-missing-signature-check
const claims = jwt.decode(token);
// ruleid: fortify.json-web-token-missing-signature-check
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });
// ok: fortify.json-web-token-missing-signature-check
jwt.verify(token, secret, { algorithms: ['HS256'] });

// ruleid: fortify.insecure-transport-weak-ssl-protocol
https.get('https://x.example', { minVersion: 'TLSv1' });
// ruleid: fortify.insecure-transport-weak-ssl-protocol
https.get('https://x.example', { secureProtocol: 'TLSv1_method' });
// ok: fortify.insecure-transport-weak-ssl-protocol
https.get('https://x.example', { minVersion: 'TLSv1.2' });

// ruleid: fortify.cookie-security-persistent-cookie
res.cookie('sid', sid, { httpOnly: true, secure: true, maxAge: 63072000000 });
// ok: fortify.cookie-security-persistent-cookie
res.cookie('sid', sid, { httpOnly: true, secure: true, maxAge: 3600000 });

// ruleid: fortify.often-misused-file-upload
const anyUpload = multer();
// ruleid: fortify.often-misused-file-upload
const diskUpload = multer({ dest: 'uploads/' });
// ok: fortify.often-misused-file-upload
const boundedUpload = multer({ dest: 'uploads/', limits: { fileSize: 5_000_000, files: 1 } });

// ruleid: fortify.weak-cryptographic-hash-hardcoded-salt
pbkdf2Sync(password, 'static-salt', 100000, 32, 'sha256');
// ok: fortify.weak-cryptographic-hash-hardcoded-salt
pbkdf2Sync(password, randomBytes(16), 100000, 32, 'sha256');
// ruleid: fortify.weak-cryptographic-hash-hardcoded-salt
scryptSync(password, 'salt', 32);

// ruleid: fortify.key-management-empty-encryption-key
createHmac('sha256', '');
// ruleid: fortify.key-management-empty-encryption-key
createCipheriv('aes-256-gcm', '', iv);
// ok: fortify.key-management-empty-encryption-key
createHmac('sha256', secret);

// ruleid: fortify.insecure-randomness-pseudo-random-bytes
pseudoRandomBytes(16);
// ok: fortify.insecure-randomness-pseudo-random-bytes
randomBytes(16);

export { claims, anyUpload, diskUpload, boundedUpload };
