function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

document.querySelectorAll('[data-generate-command]').forEach((button) => {
  button.addEventListener('click', async () => {
    const platform = button.getAttribute('data-generate-command');
    const card = button.closest('.card-body');
    const output = card.querySelector('[data-command-output]');
    const copyButton = card.querySelector('[data-copy-command]');

    try {
      const response = await fetch(`/agents/downloads/command/${platform}/`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCookie('csrftoken') || '' },
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const command = await response.text();
      output.textContent = command;
      output.classList.remove('d-none');
      copyButton.classList.remove('d-none');
      copyButton.setAttribute('data-copy', command);
    } catch (error) {
      output.textContent = `Error generando comando: ${error.message}`;
      output.classList.remove('d-none');
    }
  });
});

document.querySelectorAll('[data-copy-command]').forEach((button) => {
  button.addEventListener('click', async () => {
    const text = button.getAttribute('data-copy');
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error('No se pudo copiar', error);
    }
  });
});
