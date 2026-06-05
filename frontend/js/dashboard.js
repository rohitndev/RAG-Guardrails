/**
 * Security Analytics Dashboard — fetches /api/analytics + /api/status and
 * renders KPIs, charts (via charts.js), a high-threat feed, and active layers.
 */
const API_BASE = '';
let autoTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    loadAll();
    document.getElementById('refresh-btn').addEventListener('click', loadAll);
    document.getElementById('autorefresh-toggle').addEventListener('change', (e) => {
        if (e.target.checked) {
            autoTimer = setInterval(loadAll, 5000);
        } else {
            clearInterval(autoTimer);
            autoTimer = null;
        }
    });
});

async function loadAll() {
    await Promise.all([loadAnalytics(), loadCapabilities()]);
}

async function loadAnalytics() {
    try {
        const res = await fetch(`${API_BASE}/api/analytics`);
        const data = await res.json();
        renderKpis(data.kpis || {});
        Charts.renderTimeline(document.getElementById('chart-timeline'), data.timeline || []);
        Charts.renderDonut(document.getElementById('chart-types'), data.events_by_type || {});
        Charts.renderHBars(document.getElementById('chart-categories'), data.events_by_category || {});
        renderThreatSeverity(data.threat_histogram || {});
        renderThreatFeed(data.recent_high_threat || []);
    } catch (err) {
        console.error('Failed to load analytics:', err);
    }
}

function renderKpis(k) {
    const set = (id, v) => { document.getElementById(id).textContent = v; };
    set('kpi-total', k.total_events ?? 0);
    set('kpi-blocked', k.blocked_count ?? 0);
    set('kpi-sanitized', k.sanitized_count ?? 0);
    set('kpi-blockrate', `${Math.round((k.block_rate ?? 0) * 100)}%`);
    set('kpi-avgthreat', (k.avg_threat_level ?? 0).toFixed(2));
    set('kpi-high', k.high_threat_count ?? 0);
}

function renderThreatSeverity(hist) {
    const data = {
        'Low (0–0.4)': hist.low || 0,
        'Medium (0.4–0.7)': hist.medium || 0,
        'High (0.7–1.0)': hist.high || 0,
    };
    const host = document.getElementById('chart-threat');
    // Color-coded horizontal bars by severity.
    host.innerHTML = '';
    const colors = [Charts.PALETTE.green, Charts.PALETTE.yellow, Charts.PALETTE.red];
    const entries = Object.entries(data);
    const max = Math.max(1, ...entries.map(([, v]) => v));
    entries.forEach(([label, value], i) => {
        const row = document.createElement('div');
        row.className = 'hbar-row';
        const pct = (value / max) * 100;
        row.innerHTML = `
            <span class="hbar-label">${label}</span>
            <span class="hbar-track"><span class="hbar-fill" style="width:${pct}%;background:${colors[i]}"></span></span>
            <span class="hbar-value">${value}</span>`;
        host.appendChild(row);
    });
}

function renderThreatFeed(events) {
    const host = document.getElementById('threat-feed');
    if (!events.length) { host.innerHTML = '<div class="chart-empty">No high-threat events recorded</div>'; return; }
    host.innerHTML = events.map(e => {
        const pct = Math.round((e.threat_level || 0) * 100);
        const time = (e.timestamp || '').replace('T', ' ').slice(0, 19);
        return `
            <div class="feed-item">
                <span class="feed-threat" style="--p:${pct}">${pct}%</span>
                <div class="feed-body">
                    <div class="feed-top">
                        <span class="feed-type">${e.event_type}</span>
                        <span class="feed-time">${time}</span>
                    </div>
                    <div class="feed-preview">${escapeHtml(e.preview || '')}</div>
                </div>
            </div>`;
    }).join('');
}

async function loadCapabilities() {
    try {
        const res = await fetch(`${API_BASE}/api/status`);
        const data = await res.json();
        const caps = data.capabilities || {};
        const labels = {
            regex_guard: 'Pattern / Regex Guard',
            semantic_guard: 'Semantic Similarity Guard',
            llm_judge: 'LLM-as-Judge',
            canary: 'Canary Prompt-Leak Detection',
            presidio_pii: 'Presidio PII Engine',
        };
        const host = document.getElementById('capabilities');
        host.innerHTML = Object.entries(labels).map(([key, label]) => {
            const on = !!caps[key];
            return `<div class="cap-chip ${on ? 'on' : 'off'}">
                <span class="cap-dot"></span>${label}<span class="cap-state">${on ? 'ACTIVE' : 'off'}</span>
            </div>`;
        }).join('') + (caps.model ? `<div class="cap-chip model"><span class="cap-dot"></span>Model: ${caps.model}</div>` : '');
    } catch (err) {
        console.error('Failed to load capabilities:', err);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
