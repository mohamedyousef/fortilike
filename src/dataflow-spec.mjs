/**
 * What the global dataflow engine treats as a source, a sink, a sanitizer or a pass-through, and
 * which Fortify category a (source kind, sink) pair lands in. The shapes mirror Fortify's Node.js,
 * Express, Fastify, NestJS and browser rule families: request data, the command line, the
 * environment, the database, error objects, sensitive-by-name data, the page URL, posted messages,
 * Web Storage and network responses.
 */

/** Source kinds. A sink says which kinds it accepts and which category each produces. */
export const KIND = {
  web: 'web',           // request url/headers/query/params/body/cookies (server)
  argv: 'argv',         // process.argv
  env: 'env',           // process.env
  database: 'database', // rows read from a database
  error: 'error',       // caught errors, error.message / error.stack
  privacy: 'privacy',   // values whose name says they are private (password, secret, token, ssn...)
  dom: 'dom',           // location.*, document.URL/referrer/cookie, window.name, event.data
  storage: 'storage',   // localStorage / sessionStorage / IndexedDB reads
  network: 'network',   // fetch/XHR response bodies in browser code
  file: 'file',         // file contents read from disk
};

/** Properties of a request object that carry client data (Node http, Express, Fastify, Koa, Next). */
export const REQUEST_PROPS = new Set([
  'url', 'originalUrl', 'path', 'headers', 'rawHeaders', 'query', 'querystring', 'params', 'body', 'rawBody',
  'cookies', 'signedCookies', 'hostname', 'host', 'ip', 'ips', 'protocol', 'subdomains', 'routerPath', 'search',
  'trailers', 'files', 'file', 'fields', 'parts', 'multipart', 'raw', 'socket', 'connection',
]);
/** Request methods that return client data. */
export const REQUEST_METHODS = new Set(['header', 'headers', 'get', 'param', 'accepts', 'is', 'cookie', 'file', 'files', 'parts', 'formData', 'json', 'text', 'arrayBuffer', 'saveRequestFiles']);
/** Request properties that are safe (not client data): loggers, ids, framework handles. */
export const REQUEST_SAFE = new Set(['log', 'id', 'server', 'app', 'routeOptions', 'routeConfig', 'routeSchema', 'context', 'is404', 'session', 'user', 'method', 'validationError']);
/** Type names a request parameter can have. */
export const REQUEST_TYPES = /^(FastifyRequest|IncomingMessage|Http2ServerRequest|Request|NextApiRequest|NextRequest|express\.Request|Koa\.Request|APIGatewayProxyEvent|APIGatewayEvent|HttpRequest)\b/;
/** Parameter names that are requests when no type says otherwise. */
export const REQUEST_NAMES = /^(req|request|httpRequest|incoming|message|msg|event|evt|ctx|context)$/;
/** Type and name patterns for the response object. */
export const RESPONSE_TYPES = /^(FastifyReply|ServerResponse|Http2ServerResponse|Response|NextApiResponse|NextResponse|express\.Response|Koa\.Response|HttpResponse)\b/;
export const RESPONSE_NAMES = /^(res|resp|response|reply|rep|httpResponse|ctx\.response|context\.response)$/;
/** Loggers: by type or by name. */
export const LOGGER_TYPES = /(Logger|Pino|BaseLogger|Console|Winston|Bunyan|Signale|Log4js)/;
export const LOGGER_NAMES = /^(console|log|logger|logging|winston|pino|bunyan|debug|warn|error|info|trace|fatal)$/;
export const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'fatal', 'verbose', 'silly', 'child', 'write', 'dir', 'table', 'group', 'assert']);
export const DEBUG_LOG_METHODS = new Set(['debug', 'trace', 'verbose', 'silly']);

/** NestJS parameter decorators that bind client data (and the kind of value they bind). */
export const NEST_PARAM_DECORATORS = {
  Req: 'request', Request: 'request', Query: 'value', Body: 'value', Param: 'value', Params: 'value', Headers: 'value',
  Ip: 'value', HostParam: 'value', Session: 'session', UploadedFile: 'value', UploadedFiles: 'value', RawBody: 'value',
  Res: 'response', Response: 'response', Next: 'none',
};

/** Route registrations whose handler takes (request, response). */
export const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all', 'use', 'route', 'addHook', 'handle', 'createServer', 'createSecureServer']);
export const ROUTE_RECEIVERS = /^(app|server|router|fastify|express|instance|http|https|http2|api|koa|hono|r|this\.app|this\.server|this\.router)$/;

/** Names whose value is private information. Fortify's Privacy Violation rules match on these words. */
export const PRIVACY_NAME = /(passw(or)?d|passwd|pwd|passphrase|secret|credential|private[_-]?key|api[_-]?key|access[_-]?key|client[_-]?secret|ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cvv|cvc|iban|account[_-]?number|national[_-]?id|passport|date[_-]?of[_-]?birth|birth[_-]?date|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|bearer|authorization|jwt|otp|pin[_-]?code|mfa[_-]?code)/i;

/** Error-typed values: catch-clause variables, and these properties of anything error-like. */
export const ERROR_PROPS = new Set(['stack', 'message', 'cause', 'code', 'errno', 'syscall', 'path', 'name']);
export const ERROR_TYPES = /\b(Error|Exception|AggregateError|DOMException)\b/;

/** Calls whose result is tainted by themselves (not by their arguments). */
export const CALL_SOURCES = [
  { kind: KIND.database, label: 'a database row', match: /^(execute|executeTakeFirst|executeTakeFirstOrThrow|executeQuery|query|queryOne|queryAll|findOne|findMany|findFirst|findAll|findById|findOneBy|findBy|find|aggregate|rawQuery|\$queryRaw|\$queryRawUnsafe|get|all|run|each|fetchAll|fetchOne|selectFrom|stream|exec|toArray|lean|hget|hgetall|lrange|smembers|zrange|mget|getItem|scan|batchGet|getObject)$/,
    receiverType: /(Kysely|QueryBuilder|SelectQueryBuilder|Pool|PoolClient|Client|Connection|Repository|Model|Collection|Knex|Prisma|Sequelize|Database|Statement|Redis|Cluster|ioredis|DynamoDB|S3|Store)/ },
  { kind: KIND.network, label: 'a network response', browser: true, match: /^(json|text|arrayBuffer|blob|formData)$/, receiverType: /^(Response|Body)\b/ },
  { kind: KIND.network, label: 'a network response', browser: true, match: /^(fetch|get|post|put|patch|delete|request|axios)$/, receiverName: /^(axios|http|ky|got|superagent|\$http|api|client|httpClient)$/ },
  { kind: KIND.file, label: 'file contents', match: /^(readFile|readFileSync|readJson|readJSON|readJsonSync|readJSONSync|readdir|readdirSync|readLines|createReadStream)$/ },
];

/** Property reads that are sources on their own. */
export const PROPERTY_SOURCES = [
  { kind: KIND.argv, label: 'the command line', object: /^process$/, prop: /^argv$/ },
  { kind: KIND.env, label: 'the environment', object: /^process$/, prop: /^env$/ },
  { kind: KIND.dom, label: "the page's URL", browser: true, object: /^(window\.)?(location|document\.location|self\.location|top\.location|parent\.location)$/, prop: /^(href|search|hash|pathname|host|hostname|origin|port|protocol)$/ },
  { kind: KIND.dom, label: 'the document', browser: true, object: /^(window\.)?document$/, prop: /^(URL|documentURI|baseURI|referrer|cookie|location)$/ },
  { kind: KIND.dom, label: 'the window name', browser: true, object: /^(window|self|top|parent)$/, prop: /^name$/ },
  { kind: KIND.dom, label: 'a posted message', browser: true, object: /^(e|ev|evt|event|message|msg|messageEvent)$/, prop: /^(data|origin)$/ },
  { kind: KIND.storage, label: 'Web Storage', browser: true, object: /^(window\.)?(localStorage|sessionStorage)$/, prop: /.*/ },
];
/** Calls that read a source. */
export const CALL_PROPERTY_SOURCES = [
  { kind: KIND.storage, label: 'Web Storage', browser: true, object: /^(window\.)?(localStorage|sessionStorage)$/, method: /^(getItem|key)$/ },
  { kind: KIND.dom, label: 'a URL parameter', browser: true, object: /^(params|searchParams|urlParams|query|url\.searchParams|new URLSearchParams\(.*\)|.*\.searchParams)$/, method: /^(get|getAll|entries|values|keys|toString)$/ },
  { kind: KIND.dom, label: 'an input value', browser: true, object: /./, method: /^(getAttribute|getParameter)$/ },
];

/**
 * Sinks. `where` selects the call: `receiver` (type or name of the object the method is called on),
 * `method` (name), `module` (the import the callee comes from), `bare` (called by name). `args` are
 * the dangerous positions ('*' = any). `kinds` maps each accepted source kind to the Fortify category.
 */
const WEB_ONLY = (cat) => ({ [KIND.web]: cat, [KIND.argv]: cat, [KIND.env]: cat, [KIND.file]: cat });
const INJECTION = (cat) => ({ [KIND.web]: cat, [KIND.argv]: cat, [KIND.env]: cat, [KIND.dom]: cat, [KIND.storage]: cat, [KIND.network]: cat, [KIND.file]: cat, [KIND.database]: cat });
export const SINKS = [
  // --- Files
  { id: 'path-manipulation', where: { module: /^(node:)?fs(\/promises)?$|^fs-extra$|^graceful-fs$/, method: /^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|readdir|readdirSync|mkdir|mkdirSync|mkdtemp|mkdtempSync|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync|cp|cpSync|createReadStream|createWriteStream|open|openSync|opendir|opendirSync|stat|statSync|lstat|lstatSync|access|accessSync|exists|existsSync|realpath|realpathSync|readlink|readlinkSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync|chown|chownSync|truncate|truncateSync|utimes|utimesSync|watch|watchFile|ensureDir|ensureFile|outputFile|outputJson|readJson|remove|emptyDir|move|pathExists)$/ },
    args: [0, 1], kinds: INJECTION('Path Manipulation'), abstract: 'Untrusted data names a file the program opens, writes or removes.' },
  { id: 'path-manipulation-response', where: { receiver: 'response', method: /^(sendFile|download|sendfile|attachment|file)$/ }, args: [0], kinds: WEB_ONLY('Path Manipulation'), abstract: 'Untrusted data names the file the response serves.' },
  { id: 'path-manipulation-zip', where: { method: /^(extract|extractAll|extractAllTo|extractEntryTo|createWriteStream)$/, module: /zip|tar|yauzl|adm-zip|unzipper|extract-zip|decompress/ }, args: [0, 1], kinds: { [KIND.file]: 'Path Manipulation: Zip Entry Overwrite', [KIND.web]: 'Path Manipulation: Zip Entry Overwrite' }, abstract: 'An archive entry name chooses where the file is written.' },
  // --- Processes
  { id: 'command-injection', where: { module: /^(node:)?child_process$|^execa$|^shelljs$|^cross-spawn$|^zx$/, method: /^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa|execaSync|execaCommand|execaCommandSync|\$|command|commandSync|run)$/ }, args: [0, 1], kinds: INJECTION('Command Injection'), abstract: 'Untrusted data chooses the program or the command line a child process runs.' },
  { id: 'process-control', where: { module: /^(node:)?(child_process|module|worker_threads)$/, method: /^(fork|dlopen|createRequire|Worker)$/ }, args: [0], kinds: WEB_ONLY('Process Control'), abstract: 'Untrusted data names the program, library or module the process loads.' },
  { id: 'dangerous-file-inclusion', where: { bare: /^(require|import|importModule|loadModule)$/ }, args: [0], kinds: INJECTION('Dangerous File Inclusion'), abstract: 'Untrusted data names the module that is loaded and run.' },
  // --- Code
  { id: 'code-injection', where: { bare: /^(eval|Function|execScript|setTimeout|setInterval|setImmediate)$/, stringArg: true }, args: [0], kinds: INJECTION('Dynamic Code Evaluation: Code Injection'), abstract: 'Untrusted data is run as code.' },
  { id: 'code-injection-vm', where: { module: /^(node:)?vm$|^vm2$/, method: /^(runInThisContext|runInNewContext|runInContext|compileFunction|Script|createScript|run)$/ }, args: [0], kinds: INJECTION('Dynamic Code Evaluation: Code Injection'), abstract: 'Untrusted data is run as code.' },
  { id: 'unsafe-deserialization', where: { module: /serialize|node-serialize|serialize-to-js|cryo|funcster/, method: /^(unserialize|deserialize|parse)$/ }, args: [0], kinds: INJECTION('Dynamic Code Evaluation: Unsafe Deserialization'), abstract: 'Untrusted data is deserialized by a library that runs embedded code.' },
  { id: 'unsafe-yaml', where: { module: /^(js-yaml|yaml)$/, method: /^(load|parse|loadAll|parseDocument|parseAllDocuments)$/ }, args: [0], kinds: INJECTION('Dynamic Code Evaluation: Unsafe YAML Deserialization'), abstract: 'Untrusted YAML is parsed with a loader that can build arbitrary objects.' },
  // --- Network
  { id: 'ssrf', where: { bare: /^(fetch|request|got|axios|ky|superagent|needle|undici|phin|urllib)$/ }, args: [0], kinds: WEB_ONLY('Server-Side Request Forgery'), abstract: 'Untrusted data chooses the destination of a server-side request.' },
  { id: 'ssrf-module', where: { module: /^(node:)?https?$|^(node:)?http2$|^undici$|^axios$|^got$|^node-fetch$|^superagent$|^ky$|^needle$/, method: /^(request|get|post|put|patch|delete|head|fetch|stream|connect|Agent|Pool|Client|Dispatcher)$/ }, args: [0], kinds: WEB_ONLY('Server-Side Request Forgery'), abstract: 'Untrusted data chooses the destination of a server-side request.' },
  { id: 'ssrf-client', where: { receiverName: /^(axios|http|https|got|ky|client|httpClient|undici|dispatcher|pool|agent|this\.(http|client|httpClient|upstream|dispatcher|pool|agent))$/, method: /^(request|get|post|put|patch|delete|head|fetch|stream|pipeline|connect|upgrade)$/ }, args: [0], kinds: WEB_ONLY('Server-Side Request Forgery'), abstract: 'Untrusted data chooses the destination of a server-side request.' },
  { id: 'resource-injection', where: { module: /^(node:)?(net|tls|dgram|dns|cluster)$/, method: /^(connect|createConnection|createServer|listen|bind|lookup|resolve|send)$/ }, args: [0, 1], kinds: WEB_ONLY('Resource Injection'), abstract: 'Untrusted data chooses the port, host or address a resource is opened on.' },
  { id: 'resource-injection-listen', where: { method: /^listen$/, receiverName: /^(app|server|fastify|this\.app|this\.server|httpServer)$/ }, args: [0], kinds: WEB_ONLY('Resource Injection'), abstract: 'Untrusted data chooses the port the server listens on.' },
  { id: 'open-redirect', where: { receiver: 'response', method: /^(redirect|location)$/ }, args: [0, 1], kinds: { [KIND.web]: 'Open Redirect', [KIND.argv]: 'Open Redirect', [KIND.database]: 'Open Redirect' }, abstract: 'Untrusted data chooses where the client is redirected.' },
  { id: 'open-redirect-dom', where: { assignTarget: /^((window|self|top|parent|document)\.)?location(\.href|\.pathname|\.search)?$/ }, kinds: { [KIND.dom]: 'Open Redirect', [KIND.storage]: 'Open Redirect', [KIND.network]: 'Open Redirect' }, abstract: 'Untrusted data chooses where the page navigates.' },
  { id: 'open-redirect-dom-call', where: { receiverName: /^((window|self|top|parent|document)\.)?location$/, method: /^(assign|replace)$/ }, args: [0], kinds: { [KIND.dom]: 'Open Redirect', [KIND.storage]: 'Open Redirect', [KIND.network]: 'Open Redirect' }, abstract: 'Untrusted data chooses where the page navigates.' },
  // --- Responses
  { id: 'xss-reflected', where: { receiver: 'response', method: /^(send|end|write|json|jsonp|render|view|html|text|format|serialize)$/ }, args: ['*'],
    kinds: { [KIND.web]: 'Cross-Site Scripting: Reflected', [KIND.argv]: 'Cross-Site Scripting: Reflected', [KIND.database]: 'Cross-Site Scripting: Persistent', [KIND.file]: 'Cross-Site Scripting: Persistent', [KIND.error]: 'System Information Leak: External', [KIND.privacy]: 'Privacy Violation', [KIND.env]: 'System Information Leak: External' },
    abstract: 'Data reaches the HTTP response without being validated or encoded.' },
  { id: 'header-manipulation', where: { receiver: 'response', method: /^(setHeader|header|headers|writeHead|append|appendHeader|set|vary|type|location|removeHeader|raw\.setHeader)$/ }, args: ['*'],
    kinds: { [KIND.web]: 'Header Manipulation', [KIND.argv]: 'Header Manipulation', [KIND.database]: 'Header Manipulation', [KIND.error]: 'System Information Leak: External', [KIND.privacy]: 'Privacy Violation' },
    abstract: 'Untrusted data is written into an HTTP response header.' },
  { id: 'header-manipulation-cookies', where: { receiver: 'response', method: /^(cookie|setCookie|clearCookie|signCookie|unsignCookie)$/ }, args: ['*'], kinds: { [KIND.web]: 'Header Manipulation: Cookies', [KIND.argv]: 'Header Manipulation: Cookies', [KIND.database]: 'Header Manipulation: Cookies', [KIND.privacy]: 'Privacy Violation' }, abstract: 'Untrusted data is written into a Set-Cookie header.' },
  { id: 'xss-dom', where: { assignTarget: /\.(innerHTML|outerHTML|srcdoc|href|src|action|formAction)$/ }, kinds: { [KIND.dom]: 'Cross-Site Scripting: DOM', [KIND.storage]: 'Cross-Site Scripting: DOM', [KIND.network]: 'Cross-Site Scripting: DOM', [KIND.web]: 'Cross-Site Scripting: DOM' }, abstract: 'Untrusted data is written into the page as HTML.' },
  { id: 'xss-dom-call', where: { method: /^(insertAdjacentHTML|write|writeln|html|append|prepend|after|before|replaceWith|setAttribute|createContextualFragment|parseFromString)$/, browser: true }, args: ['*'], kinds: { [KIND.dom]: 'Cross-Site Scripting: DOM', [KIND.storage]: 'Cross-Site Scripting: DOM', [KIND.network]: 'Cross-Site Scripting: DOM' }, abstract: 'Untrusted data is written into the page as HTML.' },
  { id: 'xss-react', where: { jsxProp: /^dangerouslySetInnerHTML$/ }, kinds: { [KIND.dom]: 'Cross-Site Scripting: DOM', [KIND.storage]: 'Cross-Site Scripting: DOM', [KIND.network]: 'Cross-Site Scripting: DOM', [KIND.web]: 'Cross-Site Scripting: Reflected' }, abstract: 'Untrusted data is rendered as raw HTML by React.' },
  { id: 'script-injection', where: { assignTarget: /^script\.(src|text|textContent|innerHTML)$|\.src$/, browser: true }, kinds: { [KIND.dom]: 'Dynamic Code Evaluation: Script Injection', [KIND.storage]: 'Dynamic Code Evaluation: Script Injection', [KIND.network]: 'Dynamic Code Evaluation: Script Injection' }, abstract: 'Untrusted data names a script the page loads.' },
  { id: 'xhr-unsafe', where: { method: /^open$/, receiverType: /XMLHttpRequest/ }, args: [1], kinds: { [KIND.dom]: 'Dynamic Code Evaluation: Unsafe XMLHttpRequest', [KIND.storage]: 'Dynamic Code Evaluation: Unsafe XMLHttpRequest' }, abstract: 'Untrusted data chooses the URL an XMLHttpRequest loads.' },
  { id: 'message-posting', where: { method: /^postMessage$/ }, args: [1], kinds: { [KIND.dom]: 'HTML5: Overly Permissive Message Posting Policy' }, abstract: 'The target origin of a posted message comes from untrusted data.' },
  // --- Logs
  { id: 'log-forging', where: { receiver: 'logger', method: LOG_METHODS }, args: ['*'],
    kinds: { [KIND.web]: 'Log Forging', [KIND.argv]: 'Log Forging', [KIND.error]: 'System Information Leak: Internal', [KIND.privacy]: 'Privacy Violation', [KIND.env]: 'System Information Leak: Internal' },
    debugKinds: { [KIND.web]: 'Log Forging (debug)', [KIND.argv]: 'Log Forging (debug)' },
    abstract: 'Untrusted data is written to the log, where it can forge entries or expose details.' },
  // --- Databases
  { id: 'sql-injection', where: { method: /^(query|execute|exec|raw|sql|unsafe|run|all|get|each|prepare|\$queryRawUnsafe|\$executeRawUnsafe|literal|whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|joinRaw|fromRaw)$/, receiverType: /(Pool|Client|Connection|Kysely|Knex|Sequelize|Prisma|Database|Statement|QueryBuilder|Transaction|Sql|postgres|mysql|sqlite)/i }, args: [0], kinds: INJECTION('SQL Injection'), stringArg: true, abstract: 'Untrusted data is concatenated into an SQL statement.' },
  { id: 'sql-injection-template', where: { taggedTemplate: /^(sql|SQL|sqlRaw|raw|unsafe)$/, module: /kysely|postgres|slonik|pg|mysql|drizzle|sequelize/ }, kinds: {}, abstract: '' },
  { id: 'nosql-injection', where: { method: /^(find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|replaceOne|aggregate|countDocuments|distinct|where|\$where|mapReduce)$/, receiverType: /(Collection|Model|Query|Db|MongoClient|Mongoose)/, objectArg: true }, args: [0], kinds: INJECTION('NoSQL Injection'), abstract: 'Untrusted data shapes a NoSQL query.' },
  { id: 'access-control-database', where: { method: /^(findById|findByPk|findOne|deleteOne|updateOne|where|execute|executeTakeFirst|executeTakeFirstOrThrow|executeQuery|query|get|getItem|getObject|headObject)$/, receiverType: /(Kysely|QueryBuilder|Repository|Model|Collection|Pool|Client|Redis|S3|DynamoDB|Store)/ }, args: [0], kinds: { [KIND.web]: 'Access Control: Database' }, idArg: true, abstract: 'A record is selected by a key the client supplied, without a check that the caller owns it.' },
  // --- Objects
  { id: 'mass-assignment', where: { bare: /^(assign|merge|mergeWith|defaultsDeep|extend|assignIn|assignInWith|mixin)$/, orMethod: /^(assign|merge|mergeWith|defaultsDeep|extend|assignIn|deepmerge|mixin)$/ }, args: [1, 2, 3], kinds: { [KIND.web]: 'Mass Assignment' }, abstract: 'Client data is copied wholesale onto an object, so the client sets fields it should not.' },
  { id: 'prototype-pollution-merge', where: { bare: /^(merge|mergeWith|defaultsDeep|deepmerge|deepMerge|deepExtend|extend|mergeDeep)$/, orMethod: /^(merge|mergeWith|defaultsDeep|deepmerge|deepMerge|deepExtend|mergeDeep)$/ }, args: [1, 2, 3], kinds: INJECTION('Prototype Pollution'), abstract: 'Client data is deep-merged into an object; a __proto__ key reaches Object.prototype.' },
  { id: 'prototype-pollution-key', where: { computedAssignKey: true }, kinds: { [KIND.web]: 'Prototype Pollution', [KIND.argv]: 'Prototype Pollution', [KIND.dom]: 'Prototype Pollution', [KIND.storage]: 'Prototype Pollution', [KIND.network]: 'Prototype Pollution' }, abstract: 'Untrusted data is the property name in an assignment; __proto__ or constructor reaches every object.' },
  { id: 'setting-manipulation', where: { assignTarget: /^process\.env(\.|\[)/ }, kinds: WEB_ONLY('Setting Manipulation'), abstract: 'Untrusted data changes a setting of the running program.' },
  { id: 'setting-manipulation-call', where: { method: /^(set|enable|disable|configure|setConfig|setOption|chdir|umask|setuid|setgid|setMaxListeners|setDefaultEncoding|setTimeout|setKeepAlive)$/, receiverName: /^(app|server|fastify|process|config|settings|options|this\.(app|server|config|settings))$/ }, args: ['*'], kinds: WEB_ONLY('Setting Manipulation'), abstract: 'Untrusted data changes a setting of the running program.' },
  { id: 'trust-boundary', where: { assignTarget: /^(req|request|ctx|context)\.session(\.|\[)/ }, kinds: { [KIND.web]: 'Trust Boundary Violation' }, abstract: 'Unvalidated client data is stored in the session, where later code trusts it.' },
  { id: 'trust-boundary-storage', where: { method: /^(setItem)$/, receiverName: /^(window\.)?(localStorage|sessionStorage)$/ }, args: [1], kinds: { [KIND.dom]: 'Trust Boundary Violation', [KIND.network]: 'HTML5: Sensitive Information Disclosure via Client-Side Storage', [KIND.privacy]: 'Privacy Violation' }, abstract: 'Data is stored in Web Storage, which other scripts on the origin can read.' },
  // --- Regular expressions and templates
  { id: 'redos', where: { bare: /^RegExp$/, isNew: true }, args: [0], kinds: INJECTION('Denial of Service: Regular Expression'), abstract: 'Untrusted data becomes a regular expression the server runs.' },
  { id: 'redos-method', where: { method: /^(match|matchAll|replace|replaceAll|search|split|test|exec)$/, stringReceiver: true, regexFromTaint: true }, args: [0], kinds: INJECTION('Denial of Service: Regular Expression'), abstract: 'Untrusted data becomes a regular expression the server runs.' },
  { id: 'ssti', where: { method: /^(compile|render|renderString|renderFile|template|compileFile|precompile|compileTemplate|renderToString)$/, module: /handlebars|ejs|pug|nunjucks|mustache|lodash|underscore|dot|eta|liquid|squirrelly|twig|hogan|swig|marko|jade|velocity|vm/ }, args: [0], kinds: INJECTION('Server-Side Template Injection'), abstract: 'Untrusted data becomes the template itself, not a value in it.' },
  { id: 'denial-of-service', where: { bare: /^(setTimeout|setInterval|Array|Buffer|alloc|allocUnsafe|repeat|padStart|padEnd)$/, orMethod: /^(repeat|padStart|padEnd|alloc|allocUnsafe|allocUnsafeSlow|setTimeout|setInterval)$/, numberArg: true }, args: [0, 1], kinds: WEB_ONLY('Denial of Service'), abstract: 'Untrusted data sizes a buffer, a delay or a loop.' },
  // --- XML and JSON
  { id: 'xxe', where: { method: /^(parseXml|parseXmlString|parseHtml|parseString|parseStringPromise|parse|DOMParser|parseFromString|XMLParser|xml2js)$/, module: /libxml|xml2js|xmldom|fast-xml-parser|sax|xpath|xml/ }, args: [0], kinds: INJECTION('XML External Entity Injection'), abstract: 'Untrusted XML is parsed by a parser that resolves external entities.' },
  { id: 'xml-injection', where: { method: /^(ele|element|txt|text|att|attribute|cdata|raw|node|dat|ins|com|dec|dtd|write|writeXML|toXML|build|buildObject)$/, module: /xmlbuilder|xml2js|fast-xml-parser|xml-js|jstoxml|js2xmlparser/ }, args: ['*'], kinds: INJECTION('XML Injection'), abstract: 'Untrusted data is written into an XML document without encoding.' },
  { id: 'json-injection', where: { bare: /^(parse)$/, receiverName: /^JSON$/, concatenatedArg: true }, args: [0], kinds: WEB_ONLY('JSON Injection'), abstract: 'Untrusted data is concatenated into a JSON document before it is parsed.' },
  // --- Crypto
  { id: 'pbe-salt', where: { method: /^(pbkdf2|pbkdf2Sync|scrypt|scryptSync|hkdf|hkdfSync)$/, module: /^(node:)?crypto$/ }, args: [1], kinds: { [KIND.web]: 'Weak Cryptographic Hash: User-Controlled PBE Salt' }, abstract: 'The salt of a key-derivation function comes from the client.' },
  // --- AI
  { id: 'prompt-injection', where: { method: /^(create|complete|generate|generateText|generateContent|chat|invoke|call|predict|run|stream|streamText|sendMessage|ask)$/, receiverName: /(openai|anthropic|llm|model|chat|completions|messages|gemini|genAI|bedrock|client\.messages|client\.chat|this\.(llm|model|ai|client))/i, module: /openai|anthropic|langchain|ai|bedrock|generative-ai|cohere|mistral|ollama|vercel/ }, args: ['*'], kinds: { [KIND.web]: 'Prompt Injection', [KIND.database]: 'Prompt Injection: Persistent', [KIND.file]: 'Prompt Injection: Persistent' }, abstract: 'Untrusted data becomes part of a prompt sent to a language model.' },
  // --- Writes of private data
  { id: 'privacy-file', where: { module: /^(node:)?fs(\/promises)?$|^fs-extra$/, method: /^(writeFile|writeFileSync|appendFile|appendFileSync|outputFile|writeJson|outputJson)$/ }, args: [1], kinds: { [KIND.privacy]: 'Privacy Violation' }, abstract: 'Private data is written to a file in clear text.' },
  { id: 'privacy-cookie', where: { assignTarget: /^document\.cookie$/ }, kinds: { [KIND.privacy]: 'Privacy Violation', [KIND.dom]: 'Cross-Site Scripting: DOM' }, abstract: 'Private data is stored in a cookie.' },
  { id: 'privacy-url', where: { bare: /^(fetch|open|redirect|navigate|push|replace)$/, orMethod: /^(fetch|open|redirect|navigate|push|replace|assign)$/, urlArgWithQuery: true }, args: [0], kinds: { [KIND.privacy]: 'Privacy Violation' }, abstract: 'Private data is sent in a URL, where proxies, logs and the browser history keep it.' },
];

/** Calls that clean a value for every category. */
export const SANITIZERS = {
  all: /^(Number|parseInt|parseFloat|Boolean|BigInt|isNaN|isFinite|encodeURIComponent|encodeURI|escape|escapeHtml|escapeHTML|sanitize|sanitizeHtml|sanitizeHTML|purify|DOMPurify\.sanitize|validate|validator|z\.(string|number|enum|literal|boolean|coerce)|Object\.keys|Object\.getOwnPropertyNames|JSON\.stringify|createTextNode|hash|hashSync|createHash|digest|sign|bcrypt\.hash|argon2\.hash|crypto\.subtle\.digest|randomUUID|toFixed|toISOString|getTime|length|size|has|includes|startsWith|endsWith|indexOf|lastIndexOf|test|every|some|isArray|isInteger|isSafeInteger|isNaN|typeof|instanceof)$/,
  /** Name fragments that say a function cleans its input (Fortify honours such names only via custom rules; this tool does, so a team can name its guards). */
  nameFragments: /(^|[._])(sanitiz|escap|encod|validat|allowlist|whitelist|normaliz(e|ed)Path|safePath|resolveSafe|assert[A-Z]|ensure[A-Z]|parse(Int|Float|Id|Uuid|UUID|Enum|Bool|Boolean|Port|Number)|isSafe|isValid|toSafe|redact|mask|hash|digest|fingerprint|checksum|sha(1|256|512)|md5|hmac|etag|slugify|clamp)/,
  byCategory: {
    'Path Manipulation': /^(basename|path\.basename|safeJoin|resolveWithin|insideRoot|normalize)$/,
    'Cross-Site Scripting: Reflected': /^(escapeHtml|he\.encode|xss|encode)$/,
    'Cross-Site Scripting: DOM': /^(textContent|createTextNode|escapeHtml|he\.encode|encode)$/,
    'Open Redirect': /^(isRelativeUrl|isLocalUrl|safeReturnTo|sameOrigin|isSameOrigin|allowedRedirect)$/,
    'Header Manipulation': /^(encodeURIComponent|encodeURI|escape|String\.fromCharCode)$/,
    'Log Forging': /^(encodeURIComponent|escape|redact|sanitizeForLog|JSON\.stringify)$/,
    'SQL Injection': /^(escapeId|escape|format|sql|literal|identifier|parameterize)$/,
    'Prototype Pollution': /^(hasOwnProperty|hasOwn|Object\.hasOwn|isSafeKey|isPlainObject)$/,
  },
};

/** Methods whose result is not data from the receiver (booleans, counts, positions). */
export const CLEAN_METHODS = new Set(['length', 'size', 'has', 'includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf', 'test', 'every', 'some', 'isArray', 'localeCompare', 'equals', 'compare', 'count', 'isEmpty', 'exists', 'ok', 'hasOwnProperty', 'hasOwn', 'getTime', 'getFullYear', 'toFixed', 'charCodeAt', 'codePointAt', 'byteLength', 'digest', 'update', 'hash', 'verify', 'sign', 'randomUUID', 'randomBytes', 'now']);

/** Properties of a tainted object that are not themselves tainted (counts, booleans, handles). */
export const CLEAN_PROPS = new Set(['length', 'size', 'byteLength', 'ok', 'status', 'statusCode', 'statusText', 'redirected', 'bodyUsed', 'type', 'readable', 'writable', 'destroyed', 'closed', 'aborted', 'complete', 'constructor', 'prototype', 'log', 'server', 'app', 'id', 'socket', 'connection', 'raw', 'routeOptions', 'routerPath', 'is404', 'method', 'httpVersion']);

/** Files are browser code when they import DOM-ish things or use window/document; the engine decides per file. */
export const BROWSER_HINTS = /\b(window|document|navigator|localStorage|sessionStorage|location\.href|addEventListener|querySelector|React|useState|useEffect|jsx|tsx)\b/;

/** Types that cannot hold private data: booleans, numbers, dates, and unions of literals (enums). */
export const NON_PRIVATE_TYPE = /^(boolean|number|bigint|true|false|undefined|null|void|never|Date|RegExp)(\s*\|\s*(undefined|null))*$|^(("[^"]*"|'[^']*'|-?\d+(\.\d+)?|true|false|undefined|null)(\s*\|\s*|$))+$/;
