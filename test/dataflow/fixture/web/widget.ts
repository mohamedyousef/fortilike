export function render(el: HTMLElement): void {
  const hash = window.location.hash.slice(1);
  // df-ruleid: Cross-Site Scripting: DOM
  el.innerHTML = hash;
  // df-ok: Cross-Site Scripting: DOM
  el.textContent = hash;
  const saved = localStorage.getItem('note') ?? '';
  // df-ruleid: Cross-Site Scripting: DOM
  el.innerHTML = saved;
}
