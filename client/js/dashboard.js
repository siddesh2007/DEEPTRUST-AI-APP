import { SECTOR_CONFIG, getSectorKeyFromValue } from './sectorConfig.js';
import { calculateWeightedRisk, mapRiskToAction, getRiskLevel } from './threatEngine.js';

const activityLines = [
    'Credential stuffing blocked',
    'Suspicious IP flagged',
    'Behavioral anomaly detected',
    'Geo-risk policy executed',
    'New trusted device enrolled',
    'Liveness challenge passed'
];

const attackReasonPresets = {
    'Account Takeover': ['Credential replay correlation', 'Velocity mismatch', 'New device pattern'],
    'KYC Deepfake': ['Face texture inconsistency', 'Liveness micro-signal failure', 'Document-to-face delta'],
    'Transaction Fraud': ['Transaction intent mismatch', 'Unusual transfer behavior', 'Session anomaly'],
    'Trading Manipulation': ['Order burst anomaly', 'Behavior pattern mismatch', 'Latency spoof signature'],
    'Crypto Wallet Access': ['Device trust drop', 'Wallet route anomaly', 'Token replay pattern'],
    'API Abuse': ['Token replay signature', 'Burst traffic spike', 'Unusual endpoint sequence'],
    'Patient Record Access': ['Access time anomaly', 'Role route mismatch', 'Data-view spike'],
    'Prescription Fraud': ['Prescription path anomaly', 'Identity mismatch', 'Approval flow deviation'],
    'Deepfake Doctor Login': ['Face contour mismatch', 'Liveness micro-expression failure', 'Hospital VPN mismatch']
};

const state = {
    currentSectorKey: 'banking',
    logsPaused: false,
    autoBlockedToday: 0,
    threatIntervalId: null,
    trendIntervalId: null
};

const randomInRange = (min, max) => Math.floor(min + Math.random() * (max - min + 1));
const getCurrentSector = () => SECTOR_CONFIG[state.currentSectorKey] || SECTOR_CONFIG.banking;

const animateCounter = (element, target, suffix = '') => {
    if (!element) {
        return;
    }

    const start = performance.now();
    const duration = 700;

    const tick = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        const value = Math.round(target * progress);
        element.textContent = `${value}${suffix}`;
        if (progress < 1) {
            requestAnimationFrame(tick);
        }
    };

    requestAnimationFrame(tick);
};

const pulseValueCard = (element) => {
    const card = element?.closest('.stat-card');
    if (!card) {
        return;
    }
    card.classList.remove('value-updated');
    void card.offsetWidth;
    card.classList.add('value-updated');
};

const applySectorMetrics = () => {
    const sector = getCurrentSector();
    const mappings = [
        ['metric1Title', 'metric1Subtitle', 'activeThreats', sector.metrics.card1],
        ['metric2Title', 'metric2Subtitle', 'riskLevelValue', sector.metrics.card2],
        ['metric3Title', 'metric3Subtitle', 'trustedDevices', sector.metrics.card3],
        ['metric4Title', 'metric4Subtitle', 'anomalyScore', sector.metrics.card4]
    ];

    mappings.forEach(([titleId, subtitleId, valueId, metric]) => {
        const titleEl = document.getElementById(titleId);
        const subtitleEl = document.getElementById(subtitleId);
        const valueEl = document.getElementById(valueId);

        if (titleEl) titleEl.textContent = metric.title;
        if (subtitleEl) subtitleEl.textContent = metric.subtitle;
        if (valueEl) {
            animateCounter(valueEl, metric.value);
            pulseValueCard(valueEl);
        }
    });
};

const renderSessionTable = () => {
    const sector = getCurrentSector();
    const tbody = document.querySelector('#sessionTable tbody');
    if (!tbody) {
        return;
    }

    tbody.innerHTML = sector.users.map((user) => {
        const attrs = [
            ['data-session-risk', user.risk],
            ['data-reasons', user.reasons.join('|')],
            ['data-country', user.country],
            ['data-state', user.state],
            ['data-city', user.city],
            ['data-isp', user.isp],
            ['data-vpn', user.vpn],
            ['data-browser', user.browser],
            ['data-os', user.os],
            ['data-device-type', user.deviceType],
            ['data-resolution', user.resolution],
            ['data-fingerprint', user.fingerprint],
            ['data-login-time', user.loginTime],
            ['data-duration', user.duration],
            ['data-session-status', user.sessionStatus],
            ['data-last-activity', user.lastActivity],
            ['data-previous-attempts', user.previousAttempts],
            ['data-deepfake-confidence', user.deepfakeConfidence],
            ['data-action-taken', user.actionTaken],
            ['data-attack-type', user.attackType],
            ['data-behavior', user.behavior.join('|')]
        ].map(([key, value]) => `${key}="${String(value).replace(/"/g, '&quot;')}"`).join(' ');

        return `<tr ${attrs}><td>${user.email}</td><td><button class="ip-link" type="button" data-ip-detail>${user.ip}</button></td><td>${user.device}</td><td><div class="risk-cell"><div class="risk-bar"><span style="width:${user.risk}%"></span></div><strong>${user.risk}%</strong></div></td><td><span class="status-dot ${user.statusClass}">${user.statusLabel}</span></td><td><button class="ghost-btn" data-block-session>Block</button></td></tr>`;
    }).join('');
};

const drawThreatChart = (canvas, points) => {
    if (!canvas) {
        return;
    }

    const context = canvas.getContext('2d');
    const width = canvas.clientWidth;
    const height = canvas.height;
    canvas.width = width;

    context.clearRect(0, 0, width, height);
    context.strokeStyle = 'rgba(130, 157, 228, 0.2)';
    context.lineWidth = 1;

    for (let row = 0; row < 5; row += 1) {
        const y = (height / 5) * row;
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y);
        context.stroke();
    }

    context.strokeStyle = '#4f7fff';
    context.lineWidth = 2;
    context.beginPath();

    points.forEach((point, index) => {
        const x = (width / (points.length - 1)) * index;
        const y = height - (point / 100) * height;
        if (index === 0) {
            context.moveTo(x, y);
        } else {
            context.lineTo(x, y);
        }
    });

    context.stroke();
};

const initThreatMonitor = () => {
    const chart = document.getElementById('threatChart');
    const attempts = document.getElementById('attackAttempts');
    const blocked = document.getElementById('blockedLogins');
    const suspicious = document.getElementById('suspiciousSessions');

    let series = [18, 24, 22, 30, 26, 28, 25, 31, 27, 29, 34, 32];

    const refresh = () => {
        series = [...series.slice(1), Math.max(10, Math.min(95, series[series.length - 1] + randomInRange(-6, 6)))];
        drawThreatChart(chart, series);

        attempts.textContent = String(12 + randomInRange(0, 9));
        blocked.textContent = String(7 + randomInRange(0, 6));
        suspicious.textContent = String(3 + randomInRange(0, 4));

        [attempts, blocked, suspicious].forEach((item) => pulseValueCard(item));
    };

    refresh();
    window.setInterval(refresh, 2200);
    window.addEventListener('resize', refresh);
};

const playHighRiskTone = () => {
    try {
        const context = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = context.createOscillator();
        const gain = context.createGain();

        oscillator.type = 'sine';
        oscillator.frequency.value = 880;
        gain.gain.value = 0.03;

        oscillator.connect(gain);
        gain.connect(context.destination);
        oscillator.start();
        oscillator.stop(context.currentTime + 0.12);
    } catch {
        // Browser may block auto audio until interaction.
    }
};

const getVoiceNarration = ({ attackType, action, deepfakeConfidence }) => {
    const sector = getCurrentSector();
    if (action === 'BLOCK_ALERT_VOICE') {
        if (attackType === 'KYC Deepfake' || attackType === 'Deepfake Doctor Login') {
            return `${sector.voiceTemplates.high} Deepfake probability ${deepfakeConfidence}.`;
        }
        return sector.voiceTemplates.high;
    }
    if (action === 'STEP_UP_VERIFICATION') {
        return sector.voiceTemplates.medium;
    }
    return `${sector.label} authentication verified.`;
};

const updateAttackClassification = ({ attackType, confidence, reasons }) => {
    const typeEl = document.getElementById('attackClassType');
    const confidenceEl = document.getElementById('attackClassConfidence');
    const reasonsEl = document.getElementById('attackClassReasons');
    if (!typeEl || !confidenceEl || !reasonsEl) {
        return;
    }

    typeEl.textContent = attackType;
    confidenceEl.textContent = confidence;
    reasonsEl.innerHTML = '';
    reasons.forEach((reason) => {
        const item = document.createElement('li');
        item.textContent = reason;
        reasonsEl.appendChild(item);
    });
};

const appendVoiceLog = ({ timestamp, attackType, message, actionTaken }) => {
    const panel = document.getElementById('voiceLogPanel');
    if (!panel) {
        return;
    }

    const item = document.createElement('div');
    item.className = 'voice-log-item';
    item.innerHTML = `<strong>${timestamp} · ${attackType}</strong><div>${message}</div><div class="muted">Action: ${actionTaken}</div>`;
    panel.prepend(item);
    while (panel.children.length > 10) {
        panel.removeChild(panel.lastChild);
    }
};

const triggerVoiceAssistant = (message) => {
    const voiceNode = document.getElementById('voiceAssistant');
    if (voiceNode) {
        voiceNode.classList.add('active');
        window.setTimeout(() => voiceNode.classList.remove('active'), 1400);
    }

    if (!('speechSynthesis' in window)) {
        return;
    }

    const utterance = new SpeechSynthesisUtterance(message);
    utterance.rate = 1;
    utterance.pitch = 0.95;
    utterance.volume = 1;
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
};

const addThreatLogEntry = () => {
    const panel = document.getElementById('threatLogPanel');
    const notifyCount = document.getElementById('notifyCount');
    const autoBlockCounter = document.getElementById('autoBlockCount');
    if (!panel || state.logsPaused) {
        return;
    }

    const sector = getCurrentSector();
    const attackType = sector.threatTypes[randomInRange(0, sector.threatTypes.length - 1)];
    const sampleUser = sector.users[randomInRange(0, sector.users.length - 1)];

    const faceRisk = randomInRange(8, 95);
    const voiceRisk = randomInRange(8, 95);
    const behaviorRisk = randomInRange(8, 95);
    const ipRisk = randomInRange(8, 95);

    const riskScore = calculateWeightedRisk({
        weights: sector.riskWeights,
        signals: { face: faceRisk, voice: voiceRisk, behavior: behaviorRisk, ip: ipRisk }
    });

    const level = getRiskLevel(riskScore);
    const action = mapRiskToAction(riskScore);
    const timestamp = new Date().toLocaleTimeString('en-GB');
    const deepfakeConfidence = `${Math.max(6, Math.min(98, Math.round((faceRisk + voiceRisk) / 2)))}%`;
    const reasons = attackReasonPresets[attackType] || ['Signal anomaly detected'];
    const actionTaken = action === 'BLOCK_ALERT_VOICE' ? 'Blocked + Voice Alert' : action === 'STEP_UP_VERIFICATION' ? 'Step-up verification' : 'Allowed';
    const voiceMessage = getVoiceNarration({ attackType, action, deepfakeConfidence });

    const node = document.createElement('div');
    node.className = `threat-log-item ${level}`;
    node.innerHTML = `
        <strong>[${timestamp}] ${attackType}</strong>
        <div class="threat-log-meta">
            <span>IP: ${sampleUser.ip}</span>
            <span>Location: ${sampleUser.city}, ${sampleUser.country}</span>
            <span>Device: ${sampleUser.device}</span>
            <span>Time: ${timestamp}</span>
            <span>Type: ${attackType}</span>
            <span class="threat-log-risk">Risk: ${riskScore}%</span>
        </div>
    `;

    panel.appendChild(node);
    panel.scrollTop = panel.scrollHeight;
    while (panel.children.length > 18) {
        panel.removeChild(panel.firstChild);
    }

    if (level === 'high') {
        playHighRiskTone();
        triggerVoiceAssistant(voiceMessage);
        document.getElementById('notifyBtn')?.classList.add('high-alert');
        window.setTimeout(() => document.getElementById('notifyBtn')?.classList.remove('high-alert'), 1800);
        state.autoBlockedToday += 1;
        if (autoBlockCounter) {
            autoBlockCounter.textContent = String(state.autoBlockedToday);
        }
    }

    if (notifyCount) {
        notifyCount.textContent = String(Math.min(99, Number(notifyCount.textContent || 0) + (level === 'high' ? 1 : 0)));
    }

    updateAttackClassification({ attackType, confidence: deepfakeConfidence, reasons });
    appendVoiceLog({ timestamp, attackType, message: voiceMessage, actionTaken });
};

const startThreatFeedLoop = () => {
    if (state.threatIntervalId) {
        window.clearInterval(state.threatIntervalId);
    }
    state.threatIntervalId = window.setInterval(addThreatLogEntry, 3000);
};

const resetSectorTransientState = () => {
    const threatPanel = document.getElementById('threatLogPanel');
    const voicePanel = document.getElementById('voiceLogPanel');
    const notifyCount = document.getElementById('notifyCount');
    const autoBlockCounter = document.getElementById('autoBlockCount');

    if (threatPanel) threatPanel.innerHTML = '';
    if (voicePanel) voicePanel.innerHTML = '';
    if (notifyCount) notifyCount.textContent = '0';
    if (autoBlockCounter) autoBlockCounter.textContent = '0';
    state.autoBlockedToday = 0;

    document.getElementById('decisionPanel')?.classList.remove('open');
    document.getElementById('intelDrawer')?.classList.remove('open');
};

const applySectorProtectionView = () => {
    const sector = getCurrentSector();
    const label = document.getElementById('activeSectorLabel');
    const points = document.getElementById('sectorProtectionPoints');
    if (label) label.textContent = sector.label;
    if (points) {
        points.innerHTML = '';
        sector.protectionPoints.forEach((entry) => {
            const item = document.createElement('li');
            item.textContent = entry;
            points.appendChild(item);
        });
    }
};

const applySectorClassificationDefaults = () => {
    const sector = getCurrentSector();
    updateAttackClassification({
        attackType: sector.defaultClassification.attackType,
        confidence: sector.defaultClassification.confidence,
        reasons: sector.defaultClassification.reasons
    });
};

const applySectorContext = (sectorKey) => {
    state.currentSectorKey = sectorKey;
    const sector = getCurrentSector();

    const status = document.getElementById('pageStatus');
    if (status) {
        status.textContent = `Sector isolation active: ${sector.label}. Adaptive risk policy loaded for ${sector.roles.join(', ')}.`;
    }

    const cubeStage = document.getElementById('cubeStage');
    cubeStage?.classList.add('sector-switch');
    window.setTimeout(() => cubeStage?.classList.remove('sector-switch'), 340);

    resetSectorTransientState();
    applySectorMetrics();
    renderSessionTable();
    applySectorProtectionView();
    applySectorClassificationDefaults();

    for (let index = 0; index < 3; index += 1) {
        addThreatLogEntry();
    }
};

const initThreatLogs = () => {
    const pauseBtn = document.getElementById('pauseLogsBtn');
    if (pauseBtn) {
        pauseBtn.addEventListener('click', () => {
            state.logsPaused = !state.logsPaused;
            pauseBtn.textContent = state.logsPaused ? 'Resume Logs' : 'Pause Logs';
        });
    }
    startThreatFeedLoop();
};

const initBehaviorChart = () => {
    const chart = document.getElementById('behaviorMiniChart');
    if (!chart) return;
    chart.innerHTML = '';
    [22, 30, 28, 35, 24, 26, 20, 18].forEach((height) => {
        const node = document.createElement('span');
        node.style.height = `${height}px`;
        chart.appendChild(node);
    });
};

const initActivityFeed = () => {
    const container = document.getElementById('activityFeed');
    if (!container) return;

    const addLine = () => {
        const timestamp = new Date().toLocaleTimeString('en-GB');
        const event = activityLines[randomInRange(0, activityLines.length - 1)];
        const node = document.createElement('div');
        node.className = 'feed-item';
        node.textContent = `${timestamp} — ${event}`;

        container.appendChild(node);
        container.scrollTop = container.scrollHeight;
        while (container.children.length > 8) {
            container.removeChild(container.firstChild);
        }
    };

    for (let index = 0; index < 4; index += 1) addLine();
    window.setInterval(addLine, 3500);
};

const initRiskGauge = () => {
    const gauge = document.getElementById('riskGauge');
    const value = document.getElementById('riskGaugeValue');
    const label = document.getElementById('riskGaugeLabel');
    const riskMain = document.getElementById('anomalyScore');
    const healthRing = document.getElementById('healthRing');
    const healthValue = document.getElementById('healthValue');
    if (!gauge || !value || !label || !riskMain || !healthRing || !healthValue) {
        return;
    }

    let risk = Number(gauge.dataset.risk || 57);
    let health = Number(healthRing.dataset.health || 87);

    const apply = () => {
        gauge.style.setProperty('--risk', String(risk));
        value.textContent = String(risk);
        riskMain.textContent = String(risk);
        const high = risk > 60;
        gauge.classList.toggle('high', high);
        if (high) {
            gauge.classList.add('vibrate');
            window.setTimeout(() => gauge.classList.remove('vibrate'), 700);
        }
        label.textContent = risk < 30 ? 'Low risk posture' : risk <= 60 ? 'Medium stability' : 'High risk posture';

        health = Math.max(58, Math.min(97, 100 - Math.round(risk * 0.28)));
        healthRing.style.setProperty('--health', String(health));
        healthValue.textContent = `${health}%`;
    };

    apply();
    window.setInterval(() => {
        const next = Math.max(8, Math.min(95, risk + randomInRange(-9, 9)));
        if (next !== risk) {
            risk = next;
            apply();
        }
    }, 3600);
};

const initAttackMap = () => {
    const svg = document.getElementById('riskLinks');
    if (!svg) return;

    const points = [
        { x: 62, y: 44 },
        { x: 28, y: 34 },
        { x: 74, y: 38 },
        { x: 18, y: 53 },
        { x: 82, y: 52 }
    ];

    const renderLinks = () => {
        svg.innerHTML = '';
        const from = points[randomInRange(0, points.length - 1)];
        const to = points[randomInRange(0, points.length - 1)];
        if (from === to) return;
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', String(from.x));
        line.setAttribute('y1', String(from.y));
        line.setAttribute('x2', String(to.x));
        line.setAttribute('y2', String(to.y));
        svg.appendChild(line);
    };

    renderLinks();
    window.setInterval(renderLinks, 5000);
};

const initDecisionPanel = () => {
    const panel = document.getElementById('decisionPanel');
    const close = document.getElementById('closeDecisionPanel');
    const reasons = document.getElementById('decisionReasons');
    const score = document.getElementById('decisionScore');
    if (!panel || !close || !reasons || !score) return;

    document.addEventListener('click', (event) => {
        const row = event.target.closest('#sessionTable tbody tr');
        if (!row || event.target.closest('[data-block-session]') || event.target.closest('[data-ip-detail]')) {
            return;
        }

        score.textContent = `Risk ${row.dataset.sessionRisk || '0'}%`;
        reasons.innerHTML = '';
        String(row.dataset.reasons || '').split('|').filter(Boolean).forEach((item) => {
            const node = document.createElement('li');
            node.textContent = item;
            reasons.appendChild(node);
        });
        panel.classList.add('open');
    });

    close.addEventListener('click', () => panel.classList.remove('open'));
};

const fillList = (container, values) => {
    if (!container) return;
    container.innerHTML = '';
    values.forEach((value) => {
        const item = document.createElement('li');
        item.textContent = value;
        container.appendChild(item);
    });
};

const setFlipCardData = ({ ip, risk, type, country, device, confidence }) => {
    const bindings = {
        flipIp: ip,
        flipRisk: risk,
        flipType: type,
        flipCountry: country,
        flipDevice: device,
        flipConfidence: confidence
    };

    Object.entries(bindings).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    });
};

const initIntelDrawer = () => {
    const drawer = document.getElementById('intelDrawer');
    const closeBtn = document.getElementById('closeIntelDrawer');
    if (!drawer || !closeBtn) return;

    const fields = {
        country: document.getElementById('intelCountry'),
        state: document.getElementById('intelState'),
        city: document.getElementById('intelCity'),
        isp: document.getElementById('intelIsp'),
        vpn: document.getElementById('intelVpn'),
        browser: document.getElementById('intelBrowser'),
        os: document.getElementById('intelOs'),
        deviceType: document.getElementById('intelDeviceType'),
        resolution: document.getElementById('intelResolution'),
        fingerprint: document.getElementById('intelFingerprint'),
        loginTime: document.getElementById('intelLoginTime'),
        duration: document.getElementById('intelDuration'),
        status: document.getElementById('intelStatus'),
        lastActivity: document.getElementById('intelLastActivity'),
        attempts: document.getElementById('intelAttempts'),
        deepfakeConfidence: document.getElementById('intelDeepfakeConfidence'),
        actionTaken: document.getElementById('intelActionTaken'),
        reasons: document.getElementById('intelRiskReasons'),
        behavior: document.getElementById('intelBehavior')
    };

    document.addEventListener('click', (event) => {
        const ipButton = event.target.closest('[data-ip-detail]');
        if (!ipButton) return;

        const row = ipButton.closest('tr');
        if (!row) return;

        fields.country.textContent = row.dataset.country || '-';
        fields.state.textContent = row.dataset.state || '-';
        fields.city.textContent = row.dataset.city || '-';
        fields.isp.textContent = row.dataset.isp || '-';
        fields.vpn.textContent = row.dataset.vpn || '-';
        fields.browser.textContent = row.dataset.browser || '-';
        fields.os.textContent = row.dataset.os || '-';
        fields.deviceType.textContent = row.dataset.deviceType || '-';
        fields.resolution.textContent = row.dataset.resolution || '-';
        fields.fingerprint.textContent = row.dataset.fingerprint || '-';
        fields.loginTime.textContent = row.dataset.loginTime || '-';
        fields.duration.textContent = row.dataset.duration || '-';
        fields.status.textContent = row.dataset.sessionStatus || '-';
        fields.lastActivity.textContent = row.dataset.lastActivity || '-';
        fields.attempts.textContent = row.dataset.previousAttempts || '-';
        fields.deepfakeConfidence.textContent = row.dataset.deepfakeConfidence || '-';
        fields.actionTaken.textContent = row.dataset.actionTaken || '-';

        const reasons = String(row.dataset.reasons || '').split('|').filter(Boolean);
        const behavior = String(row.dataset.behavior || '').split('|').filter(Boolean);
        fillList(fields.reasons, reasons);
        fillList(fields.behavior, behavior);

        const attackType = row.dataset.attackType || 'Behavior Drift';
        updateAttackClassification({
            attackType,
            confidence: row.dataset.deepfakeConfidence || `${row.dataset.sessionRisk || 50}%`,
            reasons: attackReasonPresets[attackType] || reasons
        });

        setFlipCardData({
            ip: ipButton.textContent?.trim() || '-',
            risk: `${row.dataset.sessionRisk || '-'}%`,
            type: attackType,
            country: row.dataset.country || '-',
            device: row.dataset.deviceType || '-',
            confidence: row.dataset.deepfakeConfidence || '-'
        });

        drawer.classList.add('open');
    });

    closeBtn.addEventListener('click', () => drawer.classList.remove('open'));

    ['terminateSessionBtn', 'forceFaceBtn', 'markTrustedBtn', 'blacklistIpBtn', 'manualReduceRiskBtn'].forEach((id) => {
        const actionBtn = document.getElementById(id);
        actionBtn?.addEventListener('click', () => {
            actionBtn.textContent = 'Applied';
            actionBtn.disabled = true;
        });
    });
};

const initRiskTrendGraph = () => {
    const canvas = document.getElementById('riskTrendGraph');
    if (!canvas) return;

    let points = [24, 28, 25, 32, 38, 35, 42, 55, 44, 41, 48, 46, 39, 36, 33, 30, 28, 35, 49, 64, 52, 47, 44, 40];
    let hoverIndex = -1;

    const draw = () => {
        const ctx = canvas.getContext('2d');
        const width = canvas.clientWidth;
        const height = canvas.height;
        canvas.width = width;
        ctx.clearRect(0, 0, width, height);

        ctx.strokeStyle = 'rgba(130,157,228,0.2)';
        for (let row = 0; row < 4; row += 1) {
            const y = (height / 4) * row;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        ctx.beginPath();
        points.forEach((point, index) => {
            const x = (width / (points.length - 1)) * index;
            const y = height - (point / 100) * height;
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.strokeStyle = '#7aa2ff';
        ctx.lineWidth = 2;
        ctx.stroke();

        const spikeIndex = points.findIndex((value) => value >= 60);
        if (spikeIndex >= 0) {
            const x = (width / (points.length - 1)) * spikeIndex;
            const y = height - (points[spikeIndex] / 100) * height;
            ctx.fillStyle = 'rgba(239,68,68,0.9)';
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();
        }

        if (hoverIndex >= 0) {
            const x = (width / (points.length - 1)) * hoverIndex;
            const y = height - (points[hoverIndex] / 100) * height;
            ctx.fillStyle = 'rgba(229,237,255,0.95)';
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fill();
        }
    };

    canvas.addEventListener('mousemove', (event) => {
        const rect = canvas.getBoundingClientRect();
        const ratio = (event.clientX - rect.left) / rect.width;
        hoverIndex = Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1))));
        draw();
    });

    canvas.addEventListener('mouseleave', () => {
        hoverIndex = -1;
        draw();
    });

    draw();
    window.addEventListener('resize', draw);

    if (state.trendIntervalId) {
        window.clearInterval(state.trendIntervalId);
    }
    state.trendIntervalId = window.setInterval(() => {
        points = [...points.slice(1), Math.max(14, Math.min(92, points[points.length - 1] + randomInRange(-8, 8)))];
        draw();
    }, 4000);
};

const applyProfile = () => {
    const nameEl = document.getElementById('userName');
    const roleEl = document.getElementById('userRole');
    const avatarEl = document.getElementById('userAvatar');

    try {
        const profileRaw = sessionStorage.getItem('dt_active_profile');
        if (!profileRaw) return;

        const profile = JSON.parse(profileRaw);
        if (profile.fullName && nameEl) nameEl.textContent = profile.fullName;
        if (profile.role && roleEl) roleEl.textContent = profile.role;
        if (profile.avatar && avatarEl) avatarEl.src = profile.avatar;
    } catch {
        // Keep dashboard stable if profile data is unavailable.
    }
};

const initSessionActions = () => {
    document.addEventListener('click', (event) => {
        const button = event.target.closest('[data-block-session]');
        if (!button) return;

        const row = button.closest('tr');
        if (!row) return;

        const statusCell = row.children[4];
        if (statusCell) {
            statusCell.innerHTML = '<span class="status-dot high">Blocked</span>';
        }
        button.disabled = true;
        button.textContent = 'Blocked';
    });
};

const initCubeTransition = () => {
    const tabs = document.querySelectorAll('[data-cube-tab]');
    const faces = document.querySelectorAll('[data-cube-face]');
    if (!tabs.length || !faces.length) return;

    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.cubeTab;
            tabs.forEach((node) => node.classList.toggle('active', node === tab));
            faces.forEach((face) => face.classList.toggle('active', face.dataset.cubeFace === target));
        });
    });
};

const initTiltCards = () => {
    document.addEventListener('mousemove', (event) => {
        const card = event.target.closest('.stat-card, .classification-box');
        if (!card) return;

        const rect = card.getBoundingClientRect();
        const x = ((event.clientX - rect.left) / rect.width) - 0.5;
        const y = ((event.clientY - rect.top) / rect.height) - 0.5;
        card.style.transform = `perspective(900px) rotateX(${(-y * 3).toFixed(2)}deg) rotateY(${(x * 4).toFixed(2)}deg)`;
    });

    document.querySelectorAll('.stat-card, .classification-box').forEach((card) => {
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(900px) rotateX(0deg) rotateY(0deg)';
        });
    });
};

const initAttackFlip = () => {
    const flip = document.getElementById('attackFlip');
    const button = document.getElementById('flipAttackBtn');
    if (!flip || !button) return;

    button.addEventListener('click', () => {
        flip.classList.toggle('flipped');
    });
};

const initAttackModal = () => {
    const modal = document.getElementById('attackModal');
    const open = document.getElementById('openAttackModalBtn');
    const close = document.getElementById('closeAttackModalBtn');
    const backdrop = document.getElementById('attackModalBackdrop');
    const body = document.getElementById('attackModalBody');
    if (!modal || !open || !close || !backdrop || !body) return;

    open.addEventListener('click', () => {
        const reasons = Array.from(document.querySelectorAll('#intelRiskReasons li')).map((item) => item.textContent);
        const behavior = Array.from(document.querySelectorAll('#intelBehavior li')).map((item) => item.textContent);
        body.innerHTML = `
            <div><strong>Threat Summary:</strong> ${document.getElementById('attackClassType')?.textContent || 'Unknown'} (${document.getElementById('attackClassConfidence')?.textContent || 'N/A'})</div>
            <div><strong>Explainable AI Factors:</strong> ${reasons.join(' · ') || 'No factors available.'}</div>
            <div><strong>Behavioral Findings:</strong> ${behavior.join(' · ') || 'No anomalies recorded.'}</div>
            <div><strong>Response:</strong> Automated policy decision and analyst visibility enabled.</div>
        `;
        modal.classList.add('open');
    });

    const closeModal = () => modal.classList.remove('open');
    close.addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);
};

const initSectorSwitch = () => {
    const select = document.getElementById('sectorSelect');
    if (!select) return;

    select.value = state.currentSectorKey;
    select.addEventListener('change', () => {
        const nextKey = getSectorKeyFromValue(select.value);
        applySectorContext(nextKey);
    });
};

document.addEventListener('DOMContentLoaded', () => {
    initThreatMonitor();
    initRiskGauge();
    initAttackMap();
    initThreatLogs();
    initRiskTrendGraph();
    initBehaviorChart();
    initActivityFeed();
    applyProfile();
    initSessionActions();
    initDecisionPanel();
    initIntelDrawer();
    initCubeTransition();
    initTiltCards();
    initAttackFlip();
    initAttackModal();
    initSectorSwitch();

    applySectorContext(state.currentSectorKey);

    document.querySelectorAll('.circle').forEach((circle) => {
        const progress = Number(circle.dataset.progress || 0);
        circle.style.setProperty('--progress', String(progress));
    });
});
