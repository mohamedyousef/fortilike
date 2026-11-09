declare const DOMPurify: { sanitize(text: string): string };
declare const res: { setHeader(name: string, value: string): void };

const params = new URLSearchParams(location.search);
const name = params.get('name') ?? '';
const out = document.getElementById('out') as HTMLElement;
// ruleid: fortify.cross-site-scripting-dom
out.innerHTML = '<b>' + name + '</b>';
// ok: fortify.cross-site-scripting-dom
out.textContent = name;
// ok: fortify.cross-site-scripting-dom
out.innerHTML = DOMPurify.sanitize(name);
// ok: fortify.cross-site-scripting-dom
out.innerHTML = '<p class="fatal"></p>';
// ruleid: fortify.cross-site-scripting-dom
document.write(location.hash.slice(1));

window.addEventListener('message', (event) => {
  // ruleid: fortify.cross-site-scripting-dom
  document.body.insertAdjacentHTML('beforeend', event.data.html);
  // ok: fortify.cross-site-scripting-dom
  document.body.append(document.createTextNode(event.data.text));
});

// ruleid: fortify.html5-overly-permissive-message-posting-policy
window.parent.postMessage({ kind: 'ready' }, '*');
// ok: fortify.html5-overly-permissive-message-posting-policy
window.parent.postMessage({ kind: 'ready' }, 'https://hub.example');

// ruleid: fortify.html5-overly-permissive-cors-policy
res.setHeader('Access-Control-Allow-Origin', '*');
// ok: fortify.html5-overly-permissive-cors-policy
res.setHeader('Access-Control-Allow-Origin', 'https://hub.example');
// ruleid: fortify.html5-overly-permissive-cors-policy
const open = { 'Access-Control-Allow-Origin': '*' };

// ruleid: fortify.html5-overly-permissive-content-security-policy
res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");
// ok: fortify.html5-overly-permissive-content-security-policy
res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
