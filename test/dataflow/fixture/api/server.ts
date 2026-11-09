import fastify from 'fastify';
import { createServer } from 'node:http';
import { get as httpsGet } from 'node:https';
import { exec } from 'node:child_process';
import { Pool } from 'pg';
import pino from 'pino';
import express from 'express';

const app = fastify();
const log = pino();
const pool = new Pool();

app.get('/proxy', async (request, reply) => {
  const { url } = request.query as { url: string };
  // df-ruleid: Server-Side Request Forgery
  const res = await fetch(url);
  // df-ruleid: Server-Side Request Forgery
  httpsGet(url);
  // df-ruleid: Open Redirect
  reply.redirect(url);
  return res.status;
});

app.get('/user', async (request, reply) => {
  const { rows } = await pool.query('select name from users where id = $1', [String((request.params as { id: string }).id)]);
  // df-ruleid: Cross-Site Scripting: Persistent
  reply.send(rows[0].name);
  // df-ok: Cross-Site Scripting: Reflected
  reply.send(Number((request.query as { n: string }).n));
});

app.post('/merge', async (request) => {
  const body = request.body as Record<string, string>;
  const target: Record<string, string> = {};
  // df-ruleid: Prototype Pollution
  target[body.key] = body.value;
  // df-ruleid: Dynamic Code Evaluation: Code Injection
  eval(body.code);
  return target;
});

app.get('/fail', async (request, reply) => {
  try {
    await pool.query('select 1');
  } catch (err) {
    // df-ruleid: System Information Leak: Internal
    log.error(err);
    // df-ruleid: System Information Leak: External
    reply.send((err as Error).stack);
  }
});

createServer((req, res) => {
  // df-ruleid: Header Manipulation
  res.setHeader('x-path', req.url ?? '');
  // df-ruleid: Cross-Site Scripting: Reflected
  res.end(req.headers['x-name']);
}).listen(8080);

// df-ruleid: Command Injection
exec(`ls ${process.argv[2]}`);

const config = { password: process.env.DB_PASSWORD ?? '', role: 'reader' };
// df-ok: Privacy Violation
log.info(config.role);
// df-ruleid: Privacy Violation
log.info(config.password);
const userPassword: string = String(Math.random());
// df-ruleid: Privacy Violation
console.log('password is', userPassword);

const router = express();
router.get('/next', (req, res) => {
  // df-ruleid: Open Redirect
  res.redirect(req.query.next);
  // df-ruleid: Header Manipulation: Cookies
  res.cookie('theme', req.query.theme);
});

let lastUser: string | undefined;
const seen: Record<string, string> = {};
const LIMIT = 10;
router.get('/me', (req, res) => {
  // df-ruleid: Cross-Session Contamination
  lastUser = req.query.user;
  // df-ruleid: Cross-Session Contamination
  seen[req.query.id] = req.query.user;
  let scoped = 0;
  // df-ok: Cross-Session Contamination
  scoped = LIMIT + 1;
  res.json({ lastUser, scoped });
});
function helper(): void {
  // df-ok: Cross-Session Contamination
  lastUser = 'x';
}
helper();
