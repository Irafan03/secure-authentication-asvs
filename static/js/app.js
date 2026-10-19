document.addEventListener('click', (event) => {
  const toggle = event.target.closest('[data-password-toggle]');
  if (toggle) {
    const input = toggle.parentElement.querySelector('input');
    const showing = input.type === 'password';
    input.type = showing ? 'text' : 'password';
    toggle.textContent = showing ? 'Masquer' : 'Afficher';
    toggle.setAttribute('aria-pressed', String(showing));
    toggle.setAttribute('aria-label', `${showing ? 'Masquer' : 'Afficher'} ${input.labels?.[0]?.innerText || 'le mot de passe'}`);
  }

  const close = event.target.closest('.flash-close');
  if (close) close.closest('.flash')?.remove();
});

document.querySelectorAll('[data-password-input]').forEach((input) => {
  const meter = input.closest('.field')?.querySelector('.password-meter');
  const hint = input.closest('.field')?.querySelector('[data-password-hint]');
  if (!meter || !hint) return;
  input.addEventListener('input', () => {
    const length = input.value.length;
    const level = length === 0 ? 0 : length < 8 ? 1 : length < 12 ? 2 : length < 16 ? 3 : 4;
    meter.dataset.level = String(level);
    hint.textContent = length === 0
      ? 'Choisissez un mot de passe long et difficile à deviner.'
      : length < 8
        ? `${8 - length} caractère${8 - length === 1 ? '' : 's'} minimum supplémentaire${8 - length === 1 ? '' : 's'}.`
        : 'Longueur correcte. La validation de sécurité complète est effectuée à l’envoi.';
  });
});
