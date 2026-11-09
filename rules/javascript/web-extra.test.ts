import { createWriteStream, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import libxmljs from 'libxmljs';

declare const req: { query: Record<string, string>; body: Record<string, string> };
declare const res: { cookie(...args: unknown[]): void; setHeader(name: string, value: string): void };
declare const zip: { getEntries(): { entryName: string; getData(): Buffer }[] };
declare const password: string;
declare const xml: string;
declare const app: ReturnType<typeof express>;

const out = '/srv/extract';
for (const entry of zip.getEntries()) {
  // ruleid: fortify.path-manipulation-zip-entry-overwrite
  writeFileSync(join(out, entry.entryName), entry.getData());
  // ok: fortify.path-manipulation-zip-entry-overwrite
  writeFileSync(join(out, basename(entry.entryName)), entry.getData());
}

export function cookies(): void {
  // ruleid: fortify.header-manipulation-cookies
  res.cookie('lang', req.query.lang, { httpOnly: true, secure: true });
  // ok: fortify.header-manipulation-cookies
  res.cookie('lang', 'en', { httpOnly: true, secure: true });
}

// ruleid: fortify.password-management-null-password
const dbPassword = null;
// ok: fortify.password-management-null-password
const dbHost = null;

// ruleid: fortify.password-management-weak-cryptography
const stored = Buffer.from(password).toString('base64');
// ok: fortify.password-management-weak-cryptography
const encodedName = Buffer.from('report.pdf').toString('base64');

// ruleid: fortify.credential-management-hardcoded-api-credentials
const headers = { Authorization: 'Bearer sk_live_51Hx9Q2eZvKYlo2C0aBcDeFgH' };
// ok: fortify.credential-management-hardcoded-api-credentials
const dynamic = { Authorization: `Bearer ${process.env.API_TOKEN}` };

// ruleid: fortify.cross-frame-scripting
app.use(helmet({ frameguard: false }));
// ok: fortify.cross-frame-scripting
app.use(helmet());
// ruleid: fortify.cross-frame-scripting
res.setHeader('X-Frame-Options', 'ALLOWALL');

// ruleid: fortify.cross-site-request-forgery
app.use(session({ secret: process.env.SESSION_SECRET ?? '', resave: false, saveUninitialized: false }));

// ruleid: fortify.xml-external-entity-injection
libxmljs.parseXml(xml, { noent: true });
// ok: fortify.xml-external-entity-injection
libxmljs.parseXml(xml, { noent: false });

// ruleid: fortify.denial-of-service-unbounded-request-body
app.use(express.json({ limit: '500mb' }));
// ok: fortify.denial-of-service-unbounded-request-body
app.use(express.json({ limit: '1mb' }));

export { dbPassword, dbHost, stored, encodedName, headers, dynamic };
