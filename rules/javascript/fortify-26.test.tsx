import React from 'react';

declare const url: string;
declare const code: string;
declare const name: string;
declare const parentDomain: string;
declare const el: HTMLElement;

// ruleid: fortify.html5-easy-to-guess-database-name
const request = indexedDB.open('userdata', 1);
// ruleid: fortify.html5-easy-to-guess-database-name
const legacy = window.indexedDB.open('app');
// ok: fortify.html5-easy-to-guess-database-name
const scoped = indexedDB.open(`app-${name}`, 1);

export function loadScript() {
  const s = document.createElement('script');
  // ruleid: fortify.dynamic-code-evaluation-script-injection
  s.src = url;
  // ok: fortify.dynamic-code-evaluation-script-injection
  s.src = 'https://cdn.example.com/widget.js';
  document.head.appendChild(s);
  const inline = document.createElement('script');
  // ruleid: fortify.dynamic-code-evaluation-script-injection
  inline.text = code;
  document.head.appendChild(inline);
  const div = document.createElement('div');
  // ok: fortify.dynamic-code-evaluation-script-injection
  div.textContent = code;
}

// ruleid: fortify.cross-site-scripting-sop-bypass
document.domain = parentDomain;
// ok: fortify.cross-site-scripting-sop-bypass
const currentDomain = document.domain;

// ruleid: fortify.cross-site-scripting-poor-validation
el.innerHTML = encodeURIComponent(name);
// ruleid: fortify.cross-site-scripting-poor-validation
el.innerHTML = escape(name);
// ruleid: fortify.cross-site-scripting-poor-validation
el.insertAdjacentHTML('beforeend', name.replace('<', '&lt;'));
// ruleid: fortify.cross-site-scripting-poor-validation
document.write(encodeURI(name));
// ok: fortify.cross-site-scripting-poor-validation
el.textContent = name;

export const Preview = ({ html }: { html: string }) => {
  // ruleid: fortify.react-bad-practices-dangerously-set-innerhtml
  const raw = <div dangerouslySetInnerHTML={{ __html: html }} />;
  // ok: fortify.react-bad-practices-dangerously-set-innerhtml
  const safe = <div>{html}</div>;
  return (
    <section>
      {raw}
      {safe}
    </section>
  );
};

export { request, legacy, scoped, currentDomain };
