import _ from 'lodash';
import ejs from 'ejs';
import serialize from 'node-serialize';

declare const req: { body: Record<string, unknown>; params: Record<string, string>; query: Record<string, string>; session: Record<string, unknown> };
declare const res: { render(name: string, data?: unknown): void; send(body: unknown): void };
declare const User: { findById(id: unknown): unknown; create(doc: unknown): unknown; findOne(q: unknown): unknown };
declare const users: { find(q: unknown): unknown };
declare const settings: Record<string, unknown>;
declare function validateProfile(input: unknown): { name: string };

export function handle(): void {
  const key = req.query.key;
  // ruleid: fortify.prototype-pollution
  settings[key] = req.query.value;
  // ok: fortify.prototype-pollution
  settings['theme'] = req.query.value;
  // ruleid: fortify.prototype-pollution
  _.merge(settings, req.body);
  // ok: fortify.prototype-pollution
  _.merge(settings, { theme: 'dark' });

  // ruleid: fortify.mass-assignment
  User.create(req.body);
  // ok: fortify.mass-assignment
  User.create({ name: req.body.name, email: req.body.email });
  // ruleid: fortify.mass-assignment
  Object.assign(settings, req.body);

  // ruleid: fortify.nosql-injection
  users.find({ name: req.body.name });
  // ok: fortify.nosql-injection
  users.find({ name: String(req.body.name) });
  // ruleid: fortify.nosql-injection
  User.findOne({ $where: req.query.filter });

  // ruleid: fortify.dangerous-file-inclusion
  require(req.query.plugin);
  // ruleid: fortify.dangerous-file-inclusion
  res.render(req.params.page);
  // ok: fortify.dangerous-file-inclusion
  res.render('home', { user: req.params.user });

  // ruleid: fortify.server-side-template-injection
  ejs.render(req.body.template, {});
  // ok: fortify.server-side-template-injection
  ejs.render('<p><%= name %></p>', { name: req.body.name });

  // ruleid: fortify.dynamic-code-evaluation-unsafe-deserialization
  serialize.unserialize(req.body.state);
  // ok: fortify.dynamic-code-evaluation-unsafe-deserialization
  JSON.parse(String(req.body.state));

  // ruleid: fortify.access-control-database
  User.findById(req.params.id);
  // ok: fortify.access-control-database
  User.findOne({ _id: String(req.params.id), owner: req.session.userId });

  // ruleid: fortify.trust-boundary-violation
  req.session.profile = req.body.profile;
  // ok: fortify.trust-boundary-violation
  req.session.profile = validateProfile(req.body.profile);
}

// ruleid: fortify.denial-of-service-regular-expression-nested-quantifier
const words = /^(\w+)*$/;
// ruleid: fortify.denial-of-service-regular-expression-nested-quantifier
const anything = /(.*)+x/;
// ok: fortify.denial-of-service-regular-expression-nested-quantifier
const semver = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
// ok: fortify.denial-of-service-regular-expression-nested-quantifier
const simple = /^[a-z]+$/;
export { words, anything, semver, simple };
