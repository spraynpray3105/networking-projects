const state = {
  widgets: [],
  connections: {},
  selectedWidgetId: null,
};

const canvas = document.getElementById('canvas');
const palette = document.getElementById('palette');
const cardTemplate = document.getElementById('cardTemplate');
const connectionList = document.getElementById('connectionList');

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function getConfig() {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    theme: document.body.dataset.theme,
    widgets: state.widgets,
    connections: state.connections,
  };
}

function renderWidgets() {
  canvas.innerHTML = '';

  if (state.widgets.length === 0) {
    canvas.innerHTML = '<p class="muted">Drop widgets here to build your dashboard.</p>';
    return;
  }

  state.widgets.forEach((widget, idx) => {
    const node = cardTemplate.content.firstElementChild.cloneNode(true);
    node.dataset.id = widget.id;
    node.dataset.index = idx;

    node.querySelector('h3').textContent = widget.title;
    node.querySelector('.widget-type').textContent = `Type: ${widget.type}`;
    node.querySelector('.widget-source').textContent = `Source: ${widget.sourceKey || 'not set'}`;

    if (widget.id === state.selectedWidgetId) {
      node.classList.add('active');
    }

    node.addEventListener('click', () => selectWidget(widget.id));
    node.querySelector('.remove').addEventListener('click', (event) => {
      event.stopPropagation();
      state.widgets = state.widgets.filter((w) => w.id !== widget.id);
      if (state.selectedWidgetId === widget.id) {
        state.selectedWidgetId = null;
      }
      renderWidgets();
      fillWidgetForm();
    });

    node.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData('text/reorder-index', idx);
    });

    canvas.appendChild(node);
  });
}

function renderConnections() {
  const names = Object.keys(state.connections);
  connectionList.innerHTML = names.length
    ? names
        .map((name) => `<li><strong>${name}</strong> (${state.connections[name].type}) - ${state.connections[name].host}</li>`)
        .join('')
    : '<li class="muted">No connections configured yet.</li>';
}

function selectWidget(id) {
  state.selectedWidgetId = id;
  renderWidgets();
  fillWidgetForm();
}

function fillWidgetForm() {
  const widget = state.widgets.find((w) => w.id === state.selectedWidgetId);
  document.getElementById('widgetTitle').value = widget?.title || '';
  document.getElementById('widgetSource').value = widget?.sourceKey || '';
  document.getElementById('widgetRefresh').value = widget?.refresh || 30;
  document.getElementById('widgetFilters').value = (widget?.filters || []).join(',');
}

palette.querySelectorAll('.widget-item').forEach((item) => {
  item.addEventListener('dragstart', (event) => {
    event.dataTransfer.setData('text/widget-type', item.dataset.widget);
  });
});

canvas.addEventListener('dragover', (event) => event.preventDefault());
canvas.addEventListener('drop', (event) => {
  event.preventDefault();

  const widgetType = event.dataTransfer.getData('text/widget-type');
  const reorderIndex = event.dataTransfer.getData('text/reorder-index');

  if (widgetType) {
    const widget = {
      id: uid(),
      type: widgetType,
      title: widgetType.replace(/\b\w/g, (m) => m.toUpperCase()),
      sourceKey: '',
      refresh: 30,
      filters: [],
    };
    state.widgets.push(widget);
    state.selectedWidgetId = widget.id;
  } else if (reorderIndex !== '') {
    const from = Number(reorderIndex);
    const cards = [...canvas.querySelectorAll('.widget-card')];
    const dropCard = event.target.closest('.widget-card');
    const to = dropCard ? Number(dropCard.dataset.index) : state.widgets.length - 1;
    if (!Number.isNaN(from) && !Number.isNaN(to) && from !== to) {
      const [moved] = state.widgets.splice(from, 1);
      state.widgets.splice(to, 0, moved);
    }
  }

  renderWidgets();
  fillWidgetForm();
});

document.getElementById('widgetForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const widget = state.widgets.find((w) => w.id === state.selectedWidgetId);
  if (!widget) return;

  widget.title = document.getElementById('widgetTitle').value || widget.title;
  widget.sourceKey = document.getElementById('widgetSource').value;
  widget.refresh = Number(document.getElementById('widgetRefresh').value || 30);
  widget.filters = document
    .getElementById('widgetFilters')
    .value.split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  renderWidgets();
});

document.getElementById('connectionForm').addEventListener('submit', (event) => {
  event.preventDefault();

  const name = document.getElementById('connectionName').value.trim();
  if (!name) return;

  state.connections[name] = {
    type: document.getElementById('connectionType').value,
    host: document.getElementById('connectionHost').value.trim(),
    port: Number(document.getElementById('connectionPort').value || 0),
    username: document.getElementById('connectionUser').value.trim(),
    secret: document.getElementById('connectionSecret').value,
  };

  renderConnections();
  event.target.reset();
});

document.querySelectorAll('.tab').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((tab) => tab.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.remove('active'));

    button.classList.add('active');
    document.getElementById(button.dataset.tab).classList.add('active');
  });
});

document.getElementById('themePicker').addEventListener('change', (event) => {
  document.body.dataset.theme = event.target.value;
});

document.getElementById('exportBtn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(getConfig(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'security-dashboard-config.json';
  a.click();
  URL.revokeObjectURL(a.href);
});

document.getElementById('importBtn').addEventListener('click', () => {
  document.getElementById('importFile').click();
});

document.getElementById('importFile').addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;

  const content = await file.text();
  const parsed = JSON.parse(content);

  state.widgets = parsed.widgets || [];
  state.connections = parsed.connections || {};
  document.body.dataset.theme = parsed.theme || 'red-black';
  document.getElementById('themePicker').value = document.body.dataset.theme;
  state.selectedWidgetId = state.widgets[0]?.id || null;

  renderWidgets();
  renderConnections();
  fillWidgetForm();
});

document.getElementById('bundleBtn').addEventListener('click', async () => {
  const response = await fetch('/api/export_bundle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config: getConfig() }),
  });

  if (!response.ok) {
    alert('Could not build deployment bundle. Please try again.');
    return;
  }

  const blob = await response.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'security-dashboard-bundle.zip';
  a.click();
  URL.revokeObjectURL(a.href);
});

renderWidgets();
renderConnections();
