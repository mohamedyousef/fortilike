import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import https from 'node:https';
import dns from 'node:dns';
import yaml from 'js-yaml';
import Handlebars from 'handlebars';
import { ApolloServer } from '@apollo/server';
import { graphqlHTTP } from 'express-graphql';
import { generateKeyPair as joseGenerateKeyPair, importSPKI } from 'jose';
import {
  createCipheriv,
  createDiffieHellman,
  createECDH,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
  scryptSync,
} from 'node:crypto';

declare const res: express.Response;
declare const req: express.Request;
declare const reply: { setCookie(...args: unknown[]): void; header(...args: unknown[]): void };
declare const cookies: { set(...args: unknown[]): void };
declare const sid: string;
declare const text: string;
declare const typeDefs: string;
declare const resolvers: object;
declare const schema: object;
declare const src: string;
declare const ctx: object;
declare const key: Buffer;
declare const nonce: Buffer;
declare const salt: Buffer;
declare const password: string;
declare const secret: string;
declare const username: string;
declare const user: { email: string };
declare const pem: string;
declare const ip: string;
declare const logger: { info(...args: unknown[]): void };
declare const openai: { chat: { completions: { create(o: object): Promise<unknown> } } };
declare const anthropic: { messages: { create(o: object): Promise<unknown> } };
declare const model: { generateContent(o: object): Promise<unknown> };
declare const messages: unknown[];
declare const contents: unknown[];
declare const allowed: string[];

const app = express();

// ---------------------------------------------------------------- cookies
// ruleid: fortify.cookie-security-missing-samesite-attribute
res.cookie('sid', sid, { httpOnly: true, secure: true });
// ruleid: fortify.cookie-security-missing-samesite-attribute
res.cookie('sid', sid);
// ruleid: fortify.cookie-security-missing-samesite-attribute
reply.setCookie('sid', sid, { httpOnly: true, secure: true });
// ruleid: fortify.cookie-security-missing-samesite-attribute
cookies.set('sid', sid, { httpOnly: true });
// ruleid: fortify.cookie-security-missing-samesite-attribute
res.setHeader('Set-Cookie', 'sid=1; Path=/app; HttpOnly; Secure');
// ok: fortify.cookie-security-missing-samesite-attribute
res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });
// ok: fortify.cookie-security-missing-samesite-attribute
res.setHeader('Set-Cookie', 'sid=1; Path=/app; HttpOnly; Secure; SameSite=Lax');

// ruleid: fortify.cookie-security-overly-permissive-samesite-attribute
res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'none' });
// ruleid: fortify.cookie-security-overly-permissive-samesite-attribute
res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'None' });
// ruleid: fortify.cookie-security-overly-permissive-samesite-attribute
res.setHeader('Set-Cookie', 'sid=1; Path=/app; Secure; SameSite=None');
// ok: fortify.cookie-security-overly-permissive-samesite-attribute
res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'strict' });

// ruleid: fortify.cookie-security-overly-broad-domain
res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', domain: '.example.com' });
// ruleid: fortify.cookie-security-overly-broad-domain
res.setHeader('Set-Cookie', 'sid=1; Domain=.example.com; Path=/app; SameSite=Lax');
// ok: fortify.cookie-security-overly-broad-domain
res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', domain: 'app.example.com' });

// ruleid: fortify.cookie-security-overly-broad-path
res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', path: '/' });
// ruleid: fortify.cookie-security-overly-broad-path
reply.setCookie('sid', sid, { httpOnly: true, sameSite: 'lax', path: '/' });
// ruleid: fortify.cookie-security-overly-broad-path
res.setHeader('Set-Cookie', 'sid=1; Path=/; SameSite=Lax');
// ok: fortify.cookie-security-overly-broad-path
res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', path: '/app' });
// ok: fortify.cookie-security-overly-broad-path
res.setHeader('Set-Cookie', 'sid=1; Path=/app; SameSite=Lax');

// ---------------------------------------------------------------- yaml
// ruleid: fortify.dynamic-code-evaluation-unsafe-yaml-deserialization
const doc = yaml.load(text);
// ruleid: fortify.dynamic-code-evaluation-unsafe-yaml-deserialization
const docs = yaml.loadAll(text);
// ruleid: fortify.dynamic-code-evaluation-unsafe-yaml-deserialization
const viaRequire = require('js-yaml').load(text);
// ok: fortify.dynamic-code-evaluation-unsafe-yaml-deserialization
const safeDoc = yaml.load(text, { schema: yaml.JSON_SCHEMA });
// ok: fortify.dynamic-code-evaluation-unsafe-yaml-deserialization
const legacySafe = (yaml as any).safeLoad(text);

// ---------------------------------------------------------------- GraphQL
// ruleid: fortify.graphql-bad-practices-introspection-enabled
const apollo = new ApolloServer({ typeDefs, resolvers, introspection: true });
// ok: fortify.graphql-bad-practices-introspection-enabled
const apolloProd = new ApolloServer({ typeDefs, resolvers, introspection: process.env.NODE_ENV !== 'production' });
// ruleid: fortify.graphql-bad-practices-graphiql-enabled
app.use('/graphql', graphqlHTTP({ schema, graphiql: true }));
// ok: fortify.graphql-bad-practices-graphiql-enabled
app.use('/graphql', graphqlHTTP({ schema, graphiql: false }));

// ---------------------------------------------------------------- Handlebars
// ruleid: fortify.handlebars-misconfiguration-escaping-disabled
const unescaped = Handlebars.compile(src, { noEscape: true });
// ok: fortify.handlebars-misconfiguration-escaping-disabled
const escaped = Handlebars.compile(src, { strict: true });
// ruleid: fortify.handlebars-misconfiguration-prototypes-allowed
const html1 = escaped(ctx, { allowProtoPropertiesByDefault: true });
// ruleid: fortify.handlebars-misconfiguration-prototypes-allowed
const html2 = escaped(ctx, { allowProtoMethodsByDefault: true });
// ok: fortify.handlebars-misconfiguration-prototypes-allowed
const html3 = escaped(ctx, { allowedProtoProperties: { name: true } });

// ---------------------------------------------------------------- Helmet / headers
// ruleid: fortify.helmet-misconfiguration-insecure-xss-filter
app.use(helmet.xssFilter({ setOnOldIE: true }));
// ruleid: fortify.helmet-misconfiguration-insecure-xss-filter
app.use(helmet({ xssFilter: { mode: null } }));
// ok: fortify.helmet-misconfiguration-insecure-xss-filter
app.use(helmet.xssFilter());

// ruleid: fortify.html5-cross-site-scripting-protection
app.use(helmet({ xssFilter: false }));
// ruleid: fortify.html5-cross-site-scripting-protection
res.setHeader('X-XSS-Protection', '0');
// ruleid: fortify.html5-cross-site-scripting-protection
res.set('x-xss-protection', 0);
// ok: fortify.html5-cross-site-scripting-protection
res.setHeader('X-XSS-Protection', '1; mode=block');

// ruleid: fortify.html5-deprecated-header
res.setHeader('Expect-CT', 'max-age=86400, enforce');
// ruleid: fortify.html5-deprecated-header
res.setHeader('Public-Key-Pins', 'pin-sha256="abc"; max-age=5184000');
// ruleid: fortify.html5-deprecated-header
app.use(helmet({ expectCt: { maxAge: 86400 } }));
// ruleid: fortify.html5-deprecated-header
app.use(helmet.hpkp({ maxAge: 5184000, sha256s: ['abc', 'def'] }));
// ok: fortify.html5-deprecated-header
res.setHeader('Referrer-Policy', 'no-referrer');
// ok: fortify.html5-deprecated-header
app.use(helmet({ expectCt: false }));

// ruleid: fortify.html5-mime-sniffing
app.use(helmet({ noSniff: false }));
// ruleid: fortify.html5-mime-sniffing
app.use(helmet({ xContentTypeOptions: false }));
// ruleid: fortify.html5-mime-sniffing
res.setHeader('X-Content-Type-Options', 'sniff');
// ok: fortify.html5-mime-sniffing
res.setHeader('X-Content-Type-Options', 'nosniff');
// ok: fortify.html5-mime-sniffing
app.use(helmet({ noSniff: true }));

// ruleid: fortify.insecure-transport-hsts-not-set
app.use(helmet({ hsts: false }));
// ruleid: fortify.insecure-transport-hsts-not-set
app.use(helmet({ strictTransportSecurity: false }));
// ok: fortify.insecure-transport-hsts-not-set
app.use(helmet({ hsts: { maxAge: 31536000, includeSubDomains: true } }));

// ---------------------------------------------------------------- TLS strength
// ruleid: fortify.insecure-transport-weak-ssl-cipher
https.createServer({ ciphers: 'RC4-SHA:DES-CBC3-SHA:AES128-SHA' });
// ruleid: fortify.insecure-transport-weak-ssl-cipher
https.createServer({ ciphers: 'HIGH:aNULL:eNULL' });
// ok: fortify.insecure-transport-weak-ssl-cipher
https.createServer({ ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:!aNULL:!MD5' });

// ruleid: fortify.insecure-transport-insufficient-diffie-hellman-strength, fortify.weak-encryption-non-pqc-resilient-algorithm
const weakDh = createDiffieHellman(1024);
// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
const strongDh = createDiffieHellman(2048);

// ---------------------------------------------------------------- key material
// ruleid: fortify.key-management-hardcoded-hmac-key
createHmac('sha256', 'hardcoded-signing-key');
// ruleid: fortify.key-management-hardcoded-hmac-key
createHmac('sha256', Buffer.from('68617264636f646564', 'hex'));
// ok: fortify.key-management-hardcoded-hmac-key
createHmac('sha256', secret);

// ruleid: fortify.key-management-empty-hmac-key
createHmac('sha256', '');
// ruleid: fortify.key-management-empty-hmac-key
createHmac('sha256', Buffer.alloc(0));
// ok: fortify.key-management-empty-hmac-key
createHmac('sha256', randomBytes(32));

// ruleid: fortify.key-management-hardcoded-pbe-password
pbkdf2Sync('letmein', salt, 100000, 32, 'sha256');
// ruleid: fortify.key-management-hardcoded-pbe-password
scryptSync('letmein', salt, 32);
// ok: fortify.key-management-hardcoded-pbe-password
pbkdf2Sync(password, salt, 100000, 32, 'sha256');

// ruleid: fortify.key-management-empty-pbe-password
pbkdf2Sync('', salt, 100000, 32, 'sha256');
// ruleid: fortify.key-management-empty-pbe-password
scryptSync('', salt, 32);
// ok: fortify.key-management-empty-pbe-password
scryptSync(password, salt, 32);

// ruleid: fortify.key-management-null-encryption-key
createCipheriv('aes-256-gcm', null, nonce);
// ruleid: fortify.key-management-null-encryption-key
createCipheriv('aes-256-gcm', undefined, nonce);
// ok: fortify.key-management-null-encryption-key
createCipheriv('aes-256-gcm', key, nonce);

// ---------------------------------------------------------------- password-based hashing
// ruleid: fortify.weak-cryptographic-hash-empty-pbe-salt
pbkdf2Sync(password, '', 100000, 32, 'sha256');
// ruleid: fortify.weak-cryptographic-hash-empty-pbe-salt
scryptSync(password, Buffer.alloc(0), 32);
// ok: fortify.weak-cryptographic-hash-empty-pbe-salt
scryptSync(password, randomBytes(16), 32);

// ruleid: fortify.weak-cryptographic-hash-insecure-pbe-iteration-count
pbkdf2Sync(password, salt, 1000, 32, 'sha256');
// ok: fortify.weak-cryptographic-hash-insecure-pbe-iteration-count
pbkdf2Sync(password, salt, 600000, 32, 'sha256');

// ruleid: fortify.weak-cryptographic-hash-predictable-salt
pbkdf2Sync(password, username, 100000, 32, 'sha256');
// ruleid: fortify.weak-cryptographic-hash-predictable-salt
pbkdf2Sync(password, user.email, 100000, 32, 'sha256');
// ruleid: fortify.weak-cryptographic-hash-predictable-salt
scryptSync(password, Date.now().toString(), 32);
// ruleid: fortify.weak-cryptographic-hash-predictable-salt
scryptSync(password, String(Math.random()), 32);
// ok: fortify.weak-cryptographic-hash-predictable-salt
scryptSync(password, salt, 32);

// ---------------------------------------------------------------- encryption
// ruleid: fortify.weak-encryption-insecure-initialization-vector
createCipheriv('aes-256-cbc', key, '0000000000000000');
// ruleid: fortify.weak-encryption-insecure-initialization-vector
createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
// ruleid: fortify.weak-encryption-insecure-initialization-vector
createCipheriv('aes-256-cbc', key, Buffer.from('0123456789abcdef'));
const staticIv = Buffer.from('0123456789abcdef');
// ruleid: fortify.weak-encryption-insecure-initialization-vector
createCipheriv('aes-256-cbc', key, staticIv);
// ok: fortify.weak-encryption-insecure-initialization-vector
createCipheriv('aes-256-gcm', key, randomBytes(12));

// ruleid: fortify.weak-encryption-stream-cipher
createCipheriv('rc4', key, null);
// ruleid: fortify.weak-encryption-stream-cipher
createCipheriv('chacha20', key, nonce);
// ok: fortify.weak-encryption-stream-cipher
createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });

// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
generateKeyPairSync('rsa', { modulusLength: 4096 });
// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
createECDH('prime256v1');
// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
joseGenerateKeyPair('RS256');
// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
importSPKI(pem, 'ES256');
// ruleid: fortify.weak-encryption-non-pqc-resilient-algorithm
crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt']);
// ok: fortify.weak-encryption-non-pqc-resilient-algorithm
generateKeyPairSync('ml-dsa-65');
// ok: fortify.weak-encryption-non-pqc-resilient-algorithm
crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);

// ---------------------------------------------------------------- logging
// ruleid: fortify.poor-logging-practice-use-of-a-system-output-stream
console.log('started');
// ruleid: fortify.poor-logging-practice-use-of-a-system-output-stream
console.error('failed', username);
// ruleid: fortify.poor-logging-practice-use-of-a-system-output-stream
process.stdout.write('started\n');
// ok: fortify.poor-logging-practice-use-of-a-system-output-stream
logger.info('started');

// ---------------------------------------------------------------- code correctness
// ruleid: fortify.code-correctness-negative-content-length
res.setHeader('Content-Length', -1);
// ruleid: fortify.code-correctness-negative-content-length
res.set('content-length', '-1');
// ok: fortify.code-correctness-negative-content-length
res.setHeader('Content-Length', Buffer.byteLength(text));

// ---------------------------------------------------------------- LLM
// ruleid: fortify.llm-misconfiguration-unspecified-token-limit
openai.chat.completions.create({ model: 'gpt-5', messages });
// ok: fortify.llm-misconfiguration-unspecified-token-limit
openai.chat.completions.create({ model: 'gpt-5', messages, max_completion_tokens: 512 });
// ruleid: fortify.llm-misconfiguration-unspecified-token-limit
anthropic.messages.create({ model: 'claude-sonnet-4-5', messages });
// ok: fortify.llm-misconfiguration-unspecified-token-limit
anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 1024, messages });
// ruleid: fortify.llm-misconfiguration-unspecified-token-limit
model.generateContent({ contents });
// ok: fortify.llm-misconfiguration-unspecified-token-limit
model.generateContent({ contents, generationConfig: { maxOutputTokens: 256 } });

// ---------------------------------------------------------------- CORS / DNS
// ruleid: fortify.setting-manipulation-user-controlled-allow-list
app.use(cors({ origin: true, credentials: true }));
// ruleid: fortify.setting-manipulation-user-controlled-allow-list
app.use(cors({ origin: (origin, cb) => cb(null, true) }));
// ruleid: fortify.setting-manipulation-user-controlled-allow-list
app.use(cors({ origin: (origin, callback) => callback(null, origin) }));
// ruleid: fortify.setting-manipulation-user-controlled-allow-list
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
// ok: fortify.setting-manipulation-user-controlled-allow-list
app.use(cors({ origin: ['https://app.example'] }));
// ok: fortify.setting-manipulation-user-controlled-allow-list
app.use(cors({ origin: (origin, cb) => cb(null, allowed.includes(origin ?? '')) }));

// ruleid: fortify.dns-spoofing
dns.reverse(ip, (err, names) => void names);
// ruleid: fortify.dns-spoofing
dns.promises.reverse(ip);
// ruleid: fortify.dns-spoofing
if (req.hostname === 'admin.example.com') res.sendStatus(200);
// ok: fortify.dns-spoofing
dns.lookup('example.com');

export { doc, docs, viaRequire, safeDoc, legacySafe, apollo, apolloProd, unescaped, html1, html2, html3, weakDh, strongDh };
