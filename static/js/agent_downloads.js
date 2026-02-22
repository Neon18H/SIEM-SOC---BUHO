document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const text = button.getAttribute('data-copy');
    try {
      await navigator.clipboard.writeText(text);
      const toastElement = document.getElementById('copyToast');
      if (toastElement && window.bootstrap) {
        window.bootstrap.Toast.getOrCreateInstance(toastElement).show();
      }
    } catch (error) {
      console.error('No se pudo copiar', error);
    }
  });
});
