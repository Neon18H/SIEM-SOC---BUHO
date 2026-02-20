(() => {
  const toggles = document.querySelectorAll('[data-toggle-password]');
  toggles.forEach((button) => {
    button.addEventListener('click', () => {
      const inputId = button.getAttribute('data-toggle-password');
      const input = document.getElementById(inputId);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      button.innerHTML = `<i class="bi bi-eye${isPassword ? '-slash' : ''}"></i>`;
    });
  });

  const source = document.querySelector('[data-strength-source]');
  const bar = document.getElementById('strength-bar');
  const label = document.getElementById('strength-text');
  if (!source || !bar || !label) return;

  const evaluate = () => {
    const value = source.value;
    let score = 0;
    if (value.length >= 8) score++;
    if (/[A-Z]/.test(value)) score++;
    if (/[0-9]/.test(value)) score++;
    if (/[^A-Za-z0-9]/.test(value)) score++;

    const states = [
      { width: '10%', color: '#dc3545', text: 'Seguridad: muy débil' },
      { width: '35%', color: '#fd7e14', text: 'Seguridad: débil' },
      { width: '60%', color: '#ffc107', text: 'Seguridad: media' },
      { width: '80%', color: '#20c997', text: 'Seguridad: fuerte' },
      { width: '100%', color: '#0d6efd', text: 'Seguridad: excelente' },
    ];

    const state = states[score];
    bar.style.width = state.width;
    bar.style.backgroundColor = state.color;
    label.textContent = state.text;
  };

  source.addEventListener('input', evaluate);
})();
