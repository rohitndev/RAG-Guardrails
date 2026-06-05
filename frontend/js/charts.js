/**
 * Tiny dependency-free SVG chart helpers for the security dashboard.
 * No external libraries — everything renders inline so the app stays offline.
 */
const SVGNS = 'http://www.w3.org/2000/svg';

const PALETTE = {
    green: '#3fb950',
    red: '#f85149',
    blue: '#58a6ff',
    yellow: '#d29922',
    purple: '#a371f7',
    muted: '#6e7681',
    grid: '#30363d',
    text: '#8b949e',
};

const CATEGORY_COLORS = {
    instruction_override: PALETTE.red,
    jailbreak: '#ff7b72',
    roleplay: PALETTE.purple,
    prompt_injection: PALETTE.yellow,
    data_extraction: PALETTE.blue,
    sensitive_exfiltration: '#e3b341',
    output_control: '#79c0ff',
    markup_injection: '#d2a8ff',
    code_block_injection: '#7ee787',
    markdown_injection: '#56d364',
};

function el(tag, attrs = {}, text) {
    const node = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text != null) node.textContent = text;
    return node;
}

function colorFor(key, i = 0) {
    if (CATEGORY_COLORS[key]) return CATEGORY_COLORS[key];
    const rotation = [PALETTE.blue, PALETTE.green, PALETTE.purple, PALETTE.yellow, PALETTE.red];
    return rotation[i % rotation.length];
}

/** Donut chart from a {label: value} map. Renders into `container`. */
function renderDonut(container, data, opts = {}) {
    container.innerHTML = '';
    const entries = Object.entries(data).filter(([, v]) => v > 0);
    const total = entries.reduce((s, [, v]) => s + v, 0);
    if (total === 0) { container.innerHTML = '<div class="chart-empty">No data yet</div>'; return; }

    const size = 180, cx = size / 2, cy = size / 2, r = 70, stroke = 26;
    const svg = el('svg', { viewBox: `0 0 ${size} ${size}`, class: 'donut' });
    const circ = 2 * Math.PI * r;
    let offset = 0;

    entries.forEach(([label, value], i) => {
        const frac = value / total;
        const arc = el('circle', {
            cx, cy, r, fill: 'none',
            stroke: colorFor(label, i),
            'stroke-width': stroke,
            'stroke-dasharray': `${frac * circ} ${circ}`,
            'stroke-dashoffset': -offset,
            transform: `rotate(-90 ${cx} ${cy})`,
        });
        arc.style.transition = 'stroke-dasharray .6s ease';
        svg.appendChild(arc);
        offset += frac * circ;
    });

    svg.appendChild(el('text', {
        x: cx, y: cy - 4, 'text-anchor': 'middle',
        fill: PALETTE.text, 'font-size': '26', 'font-weight': '700',
    }, String(total)));
    svg.appendChild(el('text', {
        x: cx, y: cy + 16, 'text-anchor': 'middle',
        fill: PALETTE.muted, 'font-size': '11',
    }, opts.centerLabel || 'events'));

    const wrap = document.createElement('div');
    wrap.className = 'donut-wrap';
    wrap.appendChild(svg);

    const legend = document.createElement('div');
    legend.className = 'chart-legend';
    entries.forEach(([label, value], i) => {
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `<span class="legend-dot" style="background:${colorFor(label, i)}"></span>
            <span class="legend-label">${label}</span>
            <span class="legend-value">${value}</span>`;
        legend.appendChild(item);
    });
    wrap.appendChild(legend);
    container.appendChild(wrap);
}

/** Horizontal bar list from a {label: value} map, sorted desc. */
function renderHBars(container, data, opts = {}) {
    container.innerHTML = '';
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) { container.innerHTML = '<div class="chart-empty">No data yet</div>'; return; }
    const max = Math.max(...entries.map(([, v]) => v));

    entries.forEach(([label, value], i) => {
        const row = document.createElement('div');
        row.className = 'hbar-row';
        const pct = max ? (value / max) * 100 : 0;
        row.innerHTML = `
            <span class="hbar-label" title="${label}">${label}</span>
            <span class="hbar-track">
                <span class="hbar-fill" style="width:${pct}%;background:${opts.color || colorFor(label, i)}"></span>
            </span>
            <span class="hbar-value">${value}</span>`;
        container.appendChild(row);
    });
}

/** Area + line timeline. `series` = [{time, total, blocked}]. */
function renderTimeline(container, series) {
    container.innerHTML = '';
    if (!series || series.length === 0) { container.innerHTML = '<div class="chart-empty">No activity yet</div>'; return; }

    const w = 640, h = 200, padL = 32, padR = 12, padT = 14, padB = 28;
    const innerW = w - padL - padR, innerH = h - padT - padB;
    const maxV = Math.max(1, ...series.map(d => d.total));
    const n = series.length;
    const x = i => padL + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);
    const y = v => padT + innerH - (v / maxV) * innerH;

    const svg = el('svg', { viewBox: `0 0 ${w} ${h}`, class: 'timeline', preserveAspectRatio: 'none' });

    // gridlines + y labels
    for (let g = 0; g <= 4; g++) {
        const gy = padT + (g / 4) * innerH;
        svg.appendChild(el('line', { x1: padL, y1: gy, x2: w - padR, y2: gy, stroke: PALETTE.grid, 'stroke-width': 1, opacity: 0.5 }));
        svg.appendChild(el('text', { x: padL - 6, y: gy + 3, 'text-anchor': 'end', fill: PALETTE.muted, 'font-size': '9' }, String(Math.round(maxV * (1 - g / 4)))));
    }

    const linePath = (key) => series.map((d, i) => `${i === 0 ? 'M' : 'L'} ${x(i)} ${y(d[key])}`).join(' ');

    // area for total
    const area = `${linePath('total')} L ${x(n - 1)} ${y(0)} L ${x(0)} ${y(0)} Z`;
    svg.appendChild(el('path', { d: area, fill: PALETTE.blue, opacity: 0.12 }));
    svg.appendChild(el('path', { d: linePath('total'), fill: 'none', stroke: PALETTE.blue, 'stroke-width': 2 }));
    svg.appendChild(el('path', { d: linePath('blocked'), fill: 'none', stroke: PALETTE.red, 'stroke-width': 2, 'stroke-dasharray': '4 3' }));

    // points
    series.forEach((d, i) => {
        svg.appendChild(el('circle', { cx: x(i), cy: y(d.total), r: 2.5, fill: PALETTE.blue }));
        if (d.blocked > 0) svg.appendChild(el('circle', { cx: x(i), cy: y(d.blocked), r: 2.5, fill: PALETTE.red }));
    });

    // x labels (first, middle, last)
    const idxs = n <= 3 ? series.map((_, i) => i) : [0, Math.floor(n / 2), n - 1];
    idxs.forEach(i => {
        const t = series[i].time || '';
        const label = t.length >= 13 ? t.slice(11, 13) + 'h' : t.slice(-5);
        svg.appendChild(el('text', { x: x(i), y: h - 8, 'text-anchor': 'middle', fill: PALETTE.muted, 'font-size': '9' }, label));
    });

    container.appendChild(svg);
    const legend = document.createElement('div');
    legend.className = 'chart-legend inline';
    legend.innerHTML = `
        <span class="legend-item"><span class="legend-dot" style="background:${PALETTE.blue}"></span> Total events</span>
        <span class="legend-item"><span class="legend-dot" style="background:${PALETTE.red}"></span> Blocked</span>`;
    container.appendChild(legend);
}

window.Charts = { renderDonut, renderHBars, renderTimeline, PALETTE, colorFor };
