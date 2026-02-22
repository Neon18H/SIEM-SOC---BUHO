(function () {
  const parseScriptJSON = (id, fallback) => {
    const node = document.getElementById(id);
    if (!node) return fallback;
    try {
      return JSON.parse(node.textContent);
    } catch {
      return fallback;
    }
  };

  const timeSeries = parseScriptJSON('time-series-data', { labels: [], datasets: {} });
  const mitreDistribution = parseScriptJSON('mitre-distribution', {});
  const osDistribution = parseScriptJSON('os-distribution', {});
  const topAgents = parseScriptJSON('top-agents', []);

  Chart.defaults.color = '#d7def0';
  Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';

  const tooltip = {
    callbacks: {
      label(context) {
        const value = context.parsed.y ?? context.parsed;
        return `${context.dataset?.label ?? context.label}: ${value} eventos`;
      },
    },
  };

  const severityColors = {
    Critical: '#ff6384',
    High: '#ff9f40',
    Medium: '#ffcd56',
    Low: '#36a2eb',
  };

  new Chart(document.getElementById('eventsSeverityChart'), {
    type: 'line',
    data: {
      labels: timeSeries.labels,
      datasets: Object.keys(timeSeries.datasets).map((name) => ({
        label: name,
        data: timeSeries.datasets[name],
        borderColor: severityColors[name],
        backgroundColor: `${severityColors[name]}22`,
        fill: true,
        tension: 0.35,
        pointRadius: 2,
      })),
    },
    options: {
      maintainAspectRatio: false,
      plugins: { tooltip },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });

  new Chart(document.getElementById('mitreChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(mitreDistribution),
      datasets: [{
        data: Object.values(mitreDistribution),
        backgroundColor: ['#5b8cff', '#6fd3ff', '#72f5a1', '#ffd166', '#ef476f', '#b892ff'],
      }],
    },
    options: {
      maintainAspectRatio: false,
      plugins: { tooltip },
    },
  });

  new Chart(document.getElementById('osChart'), {
    type: 'pie',
    data: {
      labels: Object.keys(osDistribution),
      datasets: [{
        data: Object.values(osDistribution),
        backgroundColor: ['#36a2eb', '#4bc0c0', '#9966ff', '#ff6384', '#ff9f40'],
      }],
    },
    options: {
      maintainAspectRatio: false,
      plugins: { tooltip },
    },
  });

  new Chart(document.getElementById('agentsChart'), {
    type: 'bar',
    data: {
      labels: topAgents.map((item) => item.hostname),
      datasets: [{
        label: 'Eventos',
        data: topAgents.map((item) => item.total),
        borderRadius: 8,
        backgroundColor: '#5b8cff',
      }],
    },
    options: {
      indexAxis: 'y',
      maintainAspectRatio: false,
      plugins: { tooltip },
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
})();
