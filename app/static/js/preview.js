/* Progressive enhancement only; all navigation/filtering also works without JavaScript. */
let dialogTrigger;
document.addEventListener('click', (event) => {
  const trigger = event.target.closest('[data-dialog]');
  if (trigger) {
    dialogTrigger = trigger;
    document.getElementById(trigger.dataset.dialog).showModal();
  }
  if (event.target.closest('[data-print]')) window.print();
  if (event.target.closest('[data-close-inspector]')) {
    document.getElementById('host-inspector').replaceChildren();
    (document.querySelector('[data-last-host]') || document.getElementById('q'))?.focus();
  }
});
document.querySelectorAll('dialog').forEach((dialog) => {
  dialog.addEventListener('close', () => dialogTrigger?.focus());
});
document.addEventListener('htmx:configRequest', (event) => {
  if (event.detail.elt.matches('[data-host-link]')) {
    if (!window.matchMedia('(min-width: 1536px)').matches) {
      event.preventDefault();
      window.location.assign(event.detail.elt.href);
      return;
    }
    document.querySelectorAll('[data-last-host]').forEach((el) => el.removeAttribute('data-last-host'));
    event.detail.elt.setAttribute('data-last-host', '');
  }
});
document.addEventListener('htmx:beforeRequest', (event) => {
  event.detail.target.setAttribute('aria-busy', 'true');
  document.getElementById('refresh-error')?.setAttribute('hidden', '');
});
document.addEventListener('htmx:afterRequest', (event) => {
  event.detail.target.removeAttribute('aria-busy');
  if (event.detail.failed) {
    document.getElementById('refresh-error')?.removeAttribute('hidden');
  }
});
// Transport failures have no HTTP response and do not set detail.failed in HTMX.
for (const eventName of ['htmx:sendError', 'htmx:timeout']) {
  document.addEventListener(eventName, () => {
    document.getElementById('refresh-error')?.removeAttribute('hidden');
  });
}
document.addEventListener('htmx:afterSwap', (event) => {
  if (event.detail.target.id === 'host-inspector') {
    event.detail.target.querySelector('h2')?.focus();
  }
});
