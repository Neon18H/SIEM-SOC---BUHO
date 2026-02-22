(() => {
  const app = document.querySelector('[data-uba-app]');
  if (!app) return;

  const agentSelect = app.querySelector('[data-uba-agent]');
  const rangeSelect = app.querySelector('[data-uba-range]');
  const usersTable = app.querySelector('[data-users-table]');
  const offenseFeed = app.querySelector('[data-offense-feed]');
  let scoreChart;
  let breakdownChart;

  const severityBadge = (severity) => {
    const map = { Critical: 'danger', High: 'warning', Medium: 'info', Low: 'secondary' };
    return `<span class="badge text-bg-${map[severity] || 'secondary'}">${severity}</span>`;
  };

  const setKpis = (summary) => {
    Object.entries(summary).forEach(([key, value]) => {
      const el = app.querySelector(`[data-kpi="${key}"]`);
      if (el) el.textContent = value;
    });
  };

  const renderUsers = (items) => {
    if (!items.length) {
      usersTable.innerHTML = '<tr><td colspan="4" class="text-secondary">No hay usuarios monitoreados en este rango.</td></tr>';
      return;
    }
    usersTable.innerHTML = items.map((row) => {
      const width = Math.min(100, row.risk_score);
      return `<tr>
        <td>${row.user}</td>
        <td>${row.events}</td>
        <td><span class="badge text-bg-dark border">${row.risk_score}</span></td>
        <td><div class="uba-spark"><span style="width:${width}%"></span></div></td>
      </tr>`;
    }).join('');
  };

  const renderOffenses = (items) => {
    if (!items.length) {
      offenseFeed.innerHTML = '<div class="text-secondary">Sin ofensas recientes.</div>';
      return;
    }
    offenseFeed.innerHTML = items.map((row) => `
      <div class="uba-offense-item">
        <div class="d-flex justify-content-between align-items-center gap-2">
          <strong>${row.rule}</strong>${severityBadge(row.severity)}
        </div>
        <div class="small text-light">${row.title}</div>
        <div class="small text-secondary">${row.technique} · ${new Date(row.created_at).toLocaleString()}</div>
      </div>
    `).join('');
  };

  const renderCharts = (scoreSeries, riskBreakdown) => {
    const scoreCtx = document.getElementById('ubaScoreChart');
    const breakdownCtx = document.getElementById('ubaBreakdownChart');

    if (scoreChart) scoreChart.destroy();
    scoreChart = new Chart(scoreCtx, {
      type: 'line',
      data: {
        labels: scoreSeries.labels,
        datasets: [{ label: 'Risk', data: scoreSeries.series, borderColor: '#0dcaf0', backgroundColor: 'rgba(13,202,240,0.2)', fill: true, tension: 0.3 }]
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { suggestedMax: 100, grid: { color: '#2a3140' } }, x: { grid: { color: '#2a3140' } } } }
    });

    if (breakdownChart) breakdownChart.destroy();
    breakdownChart = new Chart(breakdownCtx, {
      type: 'doughnut',
      data: { labels: riskBreakdown.labels, datasets: [{ data: riskBreakdown.values, backgroundColor: ['#0dcaf0', '#198754', '#ffc107', '#dc3545', '#6f42c1'] }] },
      options: { plugins: { legend: { labels: { color: '#c8d0df' } } } }
    });
  };

  const loadAll = async () => {
    const agentId = agentSelect.value;
    const range = rangeSelect.value;

    usersTable.innerHTML = '<tr><td colspan="4" class="text-secondary">Cargando...</td></tr>';
    offenseFeed.innerHTML = '<div class="text-secondary">Cargando...</div>';

    const prefix = `/api/uba/${agentId}`;
    const [summary, users, offenses, series, breakdown] = await Promise.all([
      fetch(`${prefix}/summary/?range=${range}`).then((r) => r.json()),
      fetch(`${prefix}/users/?range=${range}`).then((r) => r.json()),
      fetch(`${prefix}/offenses/?range=${range}`).then((r) => r.json()),
      fetch(`${prefix}/score-series/?range=${range}`).then((r) => r.json()),
      fetch(`${prefix}/risk-breakdown/?range=${range}`).then((r) => r.json()),
    ]);

    window.history.replaceState({}, '', `/uba/endpoint/${agentId}/?range=${range}`);
    setKpis(summary);
    renderUsers(users.items || []);
    renderOffenses(offenses.items || []);
    renderCharts(series, breakdown);
  };

  if (agentSelect && rangeSelect) {
    agentSelect.addEventListener('change', loadAll);
    rangeSelect.addEventListener('change', loadAll);
    loadAll();
  }
})();
