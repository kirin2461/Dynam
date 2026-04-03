/**
 * NCP Chart Configurations
 * Chart.js instances for traffic and Geneva fitness.
 */

// ─── Shared defaults ──────────────────────────────────────────────────────

const CHART_FONT = "'JetBrains Mono', monospace";
const COLOR_ACCENT  = '#00d4ff';
const COLOR_GREEN   = '#00e5a0';
const COLOR_RED     = '#ff3b5c';
const COLOR_YELLOW  = '#ffb800';
const COLOR_PURPLE  = '#9b5de5';
const COLOR_MUTED   = 'rgba(127, 163, 192, 0.3)';
const GRID_COLOR    = 'rgba(0, 212, 255, 0.06)';

Chart.defaults.font.family = CHART_FONT;
Chart.defaults.font.size = 11;
Chart.defaults.color = '#7fa3c0';

function makeGradient(ctx, color) {
  const g = ctx.createLinearGradient(0, 0, 0, 160);
  g.addColorStop(0, color.replace(')', ', 0.3)').replace('rgb', 'rgba'));
  g.addColorStop(1, color.replace(')', ', 0.0)').replace('rgb', 'rgba'));
  return g;
}

// ─── Traffic Chart (Overview) ─────────────────────────────────────────────

let trafficChart = null;
const TRAFFIC_POINTS = 60;

function createTrafficChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const ctx = canvas.getContext('2d');

  const labels = Array(TRAFFIC_POINTS).fill('');
  const upData = Array(TRAFFIC_POINTS).fill(0);
  const downData = Array(TRAFFIC_POINTS).fill(0);

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: '↑ Загрузка',
          data: [...upData],
          borderColor: COLOR_ACCENT,
          backgroundColor: 'rgba(0, 212, 255, 0.08)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
        {
          label: '↓ Скачивание',
          data: [...downData],
          borderColor: COLOR_GREEN,
          backgroundColor: 'rgba(0, 229, 160, 0.06)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 0 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: {
            boxWidth: 12,
            boxHeight: 2,
            padding: 16,
            font: { size: 11 },
          },
        },
        tooltip: {
          backgroundColor: '#121920',
          borderColor: 'rgba(0, 212, 255, 0.3)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: (ctx) => ` ${ctx.dataset.label}: ${formatBytes(ctx.parsed.y)}/s`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: GRID_COLOR },
          ticks: { display: false },
          border: { color: GRID_COLOR },
        },
        y: {
          grid: { color: GRID_COLOR },
          border: { color: GRID_COLOR },
          ticks: {
            maxTicksLimit: 5,
            callback: (v) => formatBytes(v) + '/s',
          },
          min: 0,
        },
      },
    },
  });
  return trafficChart;
}

function updateTrafficChart(speedUp, speedDown) {
  if (!trafficChart) return;
  const ds0 = trafficChart.data.datasets[0];
  const ds1 = trafficChart.data.datasets[1];
  ds0.data.push(speedUp);
  ds1.data.push(speedDown);
  if (ds0.data.length > TRAFFIC_POINTS) ds0.data.shift();
  if (ds1.data.length > TRAFFIC_POINTS) ds1.data.shift();
  trafficChart.update('none');
}

// ─── Geneva Fitness Chart ─────────────────────────────────────────────────

let genevaChart = null;
const GENEVA_POINTS = 100;

function createGenevaChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const ctx = canvas.getContext('2d');

  genevaChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(GENEVA_POINTS).fill(''),
      datasets: [
        {
          label: 'Лучший фитнес',
          data: Array(GENEVA_POINTS).fill(0),
          borderColor: COLOR_YELLOW,
          backgroundColor: 'rgba(255, 184, 0, 0.07)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.3,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 200 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#121920',
          borderColor: 'rgba(255, 184, 0, 0.3)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: (ctx) => ` Фитнес: ${(ctx.parsed.y * 100).toFixed(1)}%`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: GRID_COLOR },
          ticks: { display: false },
          border: { color: GRID_COLOR },
        },
        y: {
          grid: { color: GRID_COLOR },
          border: { color: GRID_COLOR },
          min: 0,
          max: 1,
          ticks: {
            maxTicksLimit: 5,
            callback: (v) => (v * 100).toFixed(0) + '%',
          },
        },
      },
    },
  });
  return genevaChart;
}

function updateGenevaChart(fitnessHistory) {
  if (!genevaChart) return;
  const data = fitnessHistory.slice(-GENEVA_POINTS);
  const padded = Array(Math.max(0, GENEVA_POINTS - data.length)).fill(0).concat(data);
  genevaChart.data.datasets[0].data = padded;
  genevaChart.update('none');
}

// ─── Pipeline Throughput Chart ────────────────────────────────────────────

let pipelineChart = null;
const PIPELINE_POINTS = 60;

function createPipelineChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const ctx = canvas.getContext('2d');

  const labels = Array(PIPELINE_POINTS).fill('');
  const throughputData = Array(PIPELINE_POINTS).fill(0);

  pipelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Пропускная способность',
          data: [...throughputData],
          borderColor: COLOR_PURPLE,
          backgroundColor: 'rgba(155, 93, 229, 0.08)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 0 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: {
            boxWidth: 12,
            boxHeight: 2,
            padding: 16,
            font: { size: 11 },
          },
        },
        tooltip: {
          backgroundColor: '#121920',
          borderColor: 'rgba(155, 93, 229, 0.3)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: (ctx) => ` ${ctx.dataset.label}: ${formatNumber(ctx.parsed.y)} pps`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: GRID_COLOR },
          ticks: { display: false },
          border: { color: GRID_COLOR },
        },
        y: {
          grid: { color: GRID_COLOR },
          border: { color: GRID_COLOR },
          ticks: {
            maxTicksLimit: 5,
            callback: (v) => formatNumber(v) + ' pps',
          },
          min: 0,
        },
      },
    },
  });
  return pipelineChart;
}

function updatePipelineChart(throughput) {
  if (!pipelineChart) return;
  const ds = pipelineChart.data.datasets[0];
  ds.data.push(throughput || 0);
  if (ds.data.length > PIPELINE_POINTS) ds.data.shift();
  pipelineChart.update('none');
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Export
window.createTrafficChart = createTrafficChart;
window.updateTrafficChart = updateTrafficChart;
window.createGenevaChart = createGenevaChart;
window.updateGenevaChart = updateGenevaChart;
window.createPipelineChart = createPipelineChart;
window.updatePipelineChart = updatePipelineChart;
window.formatBytes = formatBytes;
