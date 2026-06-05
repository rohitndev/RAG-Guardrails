/**
 * RAG Guardrails Demo - Frontend Application
 */

// API Base URL
const API_BASE = '';

// State
let guardrailsEnabled = true;
let isLoading = false;

// DOM Elements
const guardrailsToggle = document.getElementById('guardrails-toggle');
const toggleStatus = document.getElementById('toggle-status');
const toggleDescription = document.getElementById('toggle-description');
const modeIndicator = document.getElementById('mode-indicator');
const guardrailIndicator = document.getElementById('guardrail-indicator');
const chatInput = document.getElementById('chat-input');
const sendBtn = document.getElementById('send-btn');
const chatMessages = document.getElementById('chat-messages');
const uploadArea = document.getElementById('upload-area');
const fileInput = document.getElementById('file-input');
const uploadStatus = document.getElementById('upload-status');
const documentList = document.getElementById('document-list');
const logsContainer = document.getElementById('logs-container');
const ollamaStatus = document.getElementById('ollama-status');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    // Set up event listeners
    setupEventListeners();
    
    // Check system status
    await checkStatus();
    
    // Load security logs
    await loadSecurityLogs();
}

function setupEventListeners() {
    // Guardrails toggle
    guardrailsToggle.addEventListener('change', handleGuardrailsToggle);
    
    // Chat input
    chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    
    chatInput.addEventListener('input', autoResizeTextarea);
    
    // Send button
    sendBtn.addEventListener('click', sendMessage);
    
    // File upload
    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    fileInput.addEventListener('change', handleFileSelect);
    
    // Example buttons
    document.querySelectorAll('.example-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            chatInput.value = btn.dataset.query;
            autoResizeTextarea();
            chatInput.focus();
        });
    });
    
    // Clear buttons
    document.getElementById('clear-docs-btn').addEventListener('click', clearDocuments);
    document.getElementById('refresh-logs-btn').addEventListener('click', loadSecurityLogs);
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
}

// Guardrails Toggle
function handleGuardrailsToggle() {
    guardrailsEnabled = guardrailsToggle.checked;
    updateGuardrailsUI();
}

function updateGuardrailsUI() {
    if (guardrailsEnabled) {
        toggleStatus.textContent = 'Guardrails ON';
        toggleDescription.textContent = 'Protected mode - Attacks will be blocked';
        modeIndicator.innerHTML = `
            <div class="mode-badge protected">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
                <span>PROTECTED</span>
            </div>
        `;
        guardrailIndicator.className = 'guardrail-indicator guardrail-on';
        guardrailIndicator.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Guardrails Active
        `;
    } else {
        toggleStatus.textContent = 'Guardrails OFF';
        toggleDescription.textContent = 'Vulnerable mode - No protection';
        modeIndicator.innerHTML = `
            <div class="mode-badge vulnerable">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <line x1="4" y1="4" x2="20" y2="20"/>
                </svg>
                <span>VULNERABLE</span>
            </div>
        `;
        guardrailIndicator.className = 'guardrail-indicator guardrail-off';
        guardrailIndicator.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            Guardrails Disabled
        `;
    }
}

// Status Check
async function checkStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/status`);
        const data = await response.json();
        
        const statusDot = ollamaStatus.querySelector('.status-dot');
        const statusText = ollamaStatus.querySelector('.status-text');
        const docsCount = document.querySelector('.docs-count');
        
        if (data.ollama_connected) {
            statusDot.className = 'status-dot connected';
            statusText.textContent = data.model_available ? 'Ollama Ready' : 'Model not found';
        } else {
            statusDot.className = 'status-dot disconnected';
            statusText.textContent = 'Ollama Offline';
        }
        
        docsCount.textContent = data.documents_count;
        
        // Update document list
        updateDocumentList(data.sources || []);
        
    } catch (error) {
        console.error('Status check failed:', error);
        const statusDot = ollamaStatus.querySelector('.status-dot');
        const statusText = ollamaStatus.querySelector('.status-text');
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'API Offline';
    }
}

// Document List
function updateDocumentList(sources) {
    if (sources.length === 0) {
        documentList.innerHTML = '<li class="empty-state">No documents uploaded</li>';
    } else {
        documentList.innerHTML = sources.map(source => `
            <li>
                <span>📄 ${source}</span>
            </li>
        `).join('');
    }
}

// Chat
async function sendMessage() {
    const query = chatInput.value.trim();
    if (!query || isLoading) return;
    
    // Clear welcome message if present
    const welcomeMessage = chatMessages.querySelector('.welcome-message');
    if (welcomeMessage) {
        welcomeMessage.remove();
    }
    
    // Add user message
    addMessage('user', query, guardrailsEnabled);
    
    // Clear input
    chatInput.value = '';
    autoResizeTextarea();
    
    // Show loading
    isLoading = true;
    sendBtn.disabled = true;
    const loadingId = addLoadingMessage();
    
    try {
        const response = await fetch(`${API_BASE}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: query,
                guardrails: guardrailsEnabled,
                temperature: 0.7,
                top_k: 5
            })
        });
        
        const data = await response.json();
        
        // Remove loading message
        removeLoadingMessage(loadingId);
        
        if (response.ok) {
            addMessage('assistant', data.answer, data.guardrails_active, {
                blocked: data.blocked,
                blockReason: data.block_reason,
                sources: data.sources,
                guardrailLogs: data.guardrail_logs,
                trace: data.trace,
                threatLevel: data.threat_level
            });
            
            // Refresh logs if in guarded mode
            if (guardrailsEnabled) {
                await loadSecurityLogs();
            }
        } else {
            addMessage('system', `Error: ${data.detail || 'Unknown error'}`, guardrailsEnabled);
        }
        
    } catch (error) {
        removeLoadingMessage(loadingId);
        addMessage('system', `Error: ${error.message}`, guardrailsEnabled);
    }
    
    isLoading = false;
    sendBtn.disabled = false;
}

function addMessage(role, content, guardrailsActive, extra = {}) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}${extra.blocked ? ' blocked' : ''}`;
    
    const avatarText = role === 'user' ? 'U' : role === 'assistant' ? 'AI' : '!';
    const senderName = role === 'user' ? 'You' : role === 'assistant' ? 'Assistant' : 'System';
    const modeClass = guardrailsActive ? 'protected' : 'vulnerable';
    const modeText = guardrailsActive ? 'Protected' : 'Vulnerable';
    
    let blockedNotice = '';
    if (extra.blocked) {
        blockedNotice = `
            <div class="message-blocked-notice">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <span>Blocked: ${extra.blockReason || 'Security threat detected'}</span>
            </div>
        `;
    }
    
    let sourcesHTML = '';
    if (extra.sources && extra.sources.length > 0) {
        sourcesHTML = `
            <div class="message-sources">
                <h5>Sources</h5>
                ${extra.sources.map(source => {
                    const scoreClass = source.score > 0.7 ? 'high' : source.score > 0.4 ? 'medium' : 'low';
                    return `
                        <div class="source-item">
                            <span class="source-score ${scoreClass}">${(source.score * 100).toFixed(0)}%</span>
                            <span>${source.file} (chunk ${source.chunk})</span>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }
    
    // Threat meter (only when guardrails were active)
    let threatMeterHTML = '';
    if (guardrailsActive && typeof extra.threatLevel === 'number') {
        const pct = Math.round(extra.threatLevel * 100);
        const color = pct >= 75 ? 'var(--accent-red)' : pct >= 45 ? 'var(--accent-yellow)' : 'var(--accent-green)';
        threatMeterHTML = `
            <div class="threat-meter">
                <span>Input threat</span>
                <span class="threat-meter-track">
                    <span class="threat-meter-fill" style="width:${pct}%;background:${color}"></span>
                </span>
                <span style="font-family:'JetBrains Mono',monospace;color:${color}">${pct}%</span>
            </div>`;
    }

    // Multi-layer guardrail trace pipeline
    let traceHTML = '';
    if (extra.trace && extra.trace.length > 0) {
        const icons = { pass: '✓', warn: '⚠', block: '✕', skipped: '○' };
        const stageNames = { input: 'Input Screening', retrieval: 'Retrieval & Context', prompt: 'Prompt', output: 'Output Scanning' };
        let lastStage = null;
        const steps = extra.trace.map(t => {
            let stageHeader = '';
            if (t.stage !== lastStage) {
                stageHeader = `<div class="trace-stage-label">${stageNames[t.stage] || t.stage}</div>`;
                lastStage = t.stage;
            }
            const scoreStr = (t.status !== 'skipped') ? `<span class="trace-score">${t.score}</span>` : '';
            return `${stageHeader}
                <div class="trace-step ${t.status}">
                    <span class="trace-icon">${icons[t.status] || '•'}</span>
                    <span class="trace-name">${t.layer}</span>
                    <span class="trace-detail">${escapeHtml(t.detail || '')}</span>
                    ${scoreStr}
                </div>`;
        }).join('');
        traceHTML = `
            <div class="guardrail-trace">
                <h5>🛡️ Guardrail Trace (${extra.trace.length} layers)</h5>
                <div class="trace-pipeline">${steps}</div>
            </div>`;
    } else if (extra.guardrailLogs && extra.guardrailLogs.length > 0) {
        traceHTML = `
            <div class="guardrail-trace">
                <h5>🛡️ Guardrail Activity</h5>
                ${extra.guardrailLogs.map(log => `
                    <div class="trace-step ${log.action === 'blocked' ? 'block' : 'warn'}">
                        <span class="trace-name">[${log.stage}] ${log.action}</span>
                        <span class="trace-detail">${log.reason || ''}</span>
                    </div>
                `).join('')}
            </div>`;
    }
    
    messageDiv.innerHTML = `
        <div class="message-header">
            <div class="message-avatar">${avatarText}</div>
            <span class="message-sender">${senderName}</span>
            <span class="message-mode ${modeClass}">${modeText}</span>
        </div>
        <div class="message-content">
            ${blockedNotice}
            <div class="message-text">${escapeHtml(content)}</div>
            ${threatMeterHTML}
            ${sourcesHTML}
            ${traceHTML}
        </div>
    `;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function addLoadingMessage() {
    const id = 'loading-' + Date.now();
    const loadingDiv = document.createElement('div');
    loadingDiv.id = id;
    loadingDiv.className = 'message assistant';
    loadingDiv.innerHTML = `
        <div class="message-header">
            <div class="message-avatar">AI</div>
            <span class="message-sender">Assistant</span>
        </div>
        <div class="message-content">
            <div class="loading-spinner"></div>
            <span style="margin-left: 12px; color: var(--text-muted);">Thinking...</span>
        </div>
    `;
    chatMessages.appendChild(loadingDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return id;
}

function removeLoadingMessage(id) {
    const loadingDiv = document.getElementById(id);
    if (loadingDiv) {
        loadingDiv.remove();
    }
}

// File Upload
function handleDragOver(e) {
    e.preventDefault();
    uploadArea.classList.add('dragging');
}

function handleDragLeave(e) {
    e.preventDefault();
    uploadArea.classList.remove('dragging');
}

function handleDrop(e) {
    e.preventDefault();
    uploadArea.classList.remove('dragging');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        uploadFile(files[0]);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFile(files[0]);
    }
}

async function uploadFile(file) {
    const validExtensions = ['.pdf', '.txt'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!validExtensions.includes(ext)) {
        showUploadStatus('Invalid file type. Please upload PDF or TXT files.', 'error');
        return;
    }
    
    showUploadStatus('Uploading and processing...', 'loading');
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showUploadStatus(`✓ ${data.filename} (${data.chunks_created} chunks)`, 'success');
            await checkStatus();
        } else {
            showUploadStatus(`Error: ${data.detail}`, 'error');
        }
        
    } catch (error) {
        showUploadStatus(`Upload failed: ${error.message}`, 'error');
    }
    
    // Clear file input
    fileInput.value = '';
}

function showUploadStatus(message, type) {
    uploadStatus.textContent = message;
    uploadStatus.className = `upload-status ${type}`;
    
    if (type === 'success') {
        setTimeout(() => {
            uploadStatus.textContent = '';
            uploadStatus.className = 'upload-status';
        }, 3000);
    }
}

// Security Logs
async function loadSecurityLogs() {
    try {
        const response = await fetch(`${API_BASE}/api/logs?limit=20`);
        const data = await response.json();
        
        if (data.events && data.events.length > 0) {
            logsContainer.innerHTML = data.events.map(event => {
                const typeClass = event.action_taken === 'blocked' ? 'blocked' : 
                                  event.action_taken === 'sanitized' ? 'warning' : 'info';
                return `
                    <div class="log-entry ${typeClass}">
                        <span class="log-type">${event.event_type}</span>
                        <span class="log-preview">${event.input_preview}</span>
                    </div>
                `;
            }).join('');
        } else {
            logsContainer.innerHTML = '<div class="empty-state">No security events</div>';
        }
        
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

async function clearDocuments() {
    if (!confirm('Are you sure you want to clear all documents?')) return;
    
    try {
        await fetch(`${API_BASE}/api/documents`, { method: 'DELETE' });
        await checkStatus();
    } catch (error) {
        console.error('Failed to clear documents:', error);
    }
}

async function clearLogs() {
    try {
        await fetch(`${API_BASE}/api/logs`, { method: 'DELETE' });
        await loadSecurityLogs();
    } catch (error) {
        console.error('Failed to clear logs:', error);
    }
}

// Utilities
function autoResizeTextarea() {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 150) + 'px';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/\n/g, '<br>');
}
