// ── Theme toggle ──────────────────────────────────────────
const html        = document.documentElement;
const themeToggle = document.getElementById('themeToggle');
const saved = localStorage.getItem('tl-theme') || 'light';
html.setAttribute('data-theme', saved);
if (themeToggle) themeToggle.textContent = saved === 'dark' ? '☀️' : '🌙';

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('tl-theme', next);
    themeToggle.textContent = next === 'dark' ? '☀️' : '🌙';
  });
}

// ── DOM refs (present on home + demo pages) ───────────────
const urlInput      = document.getElementById('urlInput');
const analyzeBtn    = document.getElementById('analyzeBtn');
const clearBtn      = document.getElementById('clearBtn');
const resultSection = document.getElementById('resultSection');
const errorToast    = document.getElementById('errorToast');
const errorMsg      = document.getElementById('errorMsg');
const verdictCard   = document.getElementById('verdictCard');
const verdictIcon   = document.getElementById('verdictIcon');
const verdictLabel  = document.getElementById('verdictLabel');
const verdictUrl    = document.getElementById('verdictUrl');
const scoreNum      = document.getElementById('scoreNum');
const ringFill      = document.getElementById('ringFill');
const riskList      = document.getElementById('riskList');
const riskCount     = document.getElementById('riskCount');
const positiveList  = document.getElementById('positiveList');
const positiveCount = document.getElementById('positiveCount');
const techGrid      = document.getElementById('techGrid');
const sslInfo       = document.getElementById('sslInfo');
const domainInfo    = document.getElementById('domainInfo');
const downloadReport  = document.getElementById('downloadReport');
const analyzeAnother  = document.getElementById('analyzeAnother');

// ── Sample chips ──────────────────────────────────────────
document.querySelectorAll('.sample-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    if (!urlInput) return;
    urlInput.value = chip.dataset.url;
    clearBtn && clearBtn.classList.add('visible');
    urlInput.focus();
  });
});

if (urlInput) {
  urlInput.addEventListener('input', () => {
    clearBtn && clearBtn.classList.toggle('visible', urlInput.value.length > 0);
  });
  urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') runAnalysis(); });
}
if (clearBtn) {
  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.classList.remove('visible');
    urlInput.focus();
  });
}
if (analyzeBtn) analyzeBtn.addEventListener('click', runAnalysis);

// ── Analysis ──────────────────────────────────────────────
async function runAnalysis() {
  const url = urlInput ? urlInput.value.trim() : '';
  if (!url) { showError('Please enter a URL first.'); return; }
  setLoading(true);
  hideError();
  if (resultSection) resultSection.classList.add('hidden');

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderResult(data);
    if (resultSection) {
      resultSection.classList.remove('hidden');
      resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  } catch (err) {
    showError(err.message || 'Analysis failed. Check the URL and try again.');
  } finally {
    setLoading(false);
  }
}

// ── Render result ─────────────────────────────────────────
function renderResult(data) {
  const colorMap     = { danger: 'danger', warning: 'warning', safe: 'safe' };
  const iconMap      = { PHISHING: '🚨', SUSPICIOUS: '⚠️', SAFE: '✅' };
  const ringColorMap = { danger: '#dc2626', warning: '#d97706', safe: '#16a34a' };

  if (verdictCard)  verdictCard.className  = 'verdict-card ' + (colorMap[data.color] || '');
  if (verdictIcon)  verdictIcon.textContent  = iconMap[data.verdict] || '🔍';
  if (verdictLabel) verdictLabel.textContent = data.verdict_label;
  if (verdictUrl)   verdictUrl.textContent   = data.url;

  animateScore(data.score, ringColorMap[data.color] || '#e11d48');

  // Risk factors
  if (riskList) {
    if (data.reasons && data.reasons.length > 0) {
      if (riskCount) riskCount.textContent = data.reasons.length;
      riskList.innerHTML = data.reasons.map(([reason, severity]) => `
        <div class="risk-item ${severity}">
          <span class="risk-badge">${severity}</span>
          <span>${reason}</span>
        </div>`).join('');
    } else {
      if (riskCount) riskCount.textContent = '0';
      riskList.innerHTML = '<div class="empty-state">✅ No risk factors detected</div>';
    }
  }

  // Positive signals
  if (positiveList) {
    if (data.positive_signals && data.positive_signals.length > 0) {
      if (positiveCount) positiveCount.textContent = data.positive_signals.length;
      positiveList.innerHTML = data.positive_signals.map(s => `<div class="positive-item">✓ ${s}</div>`).join('');
    } else {
      if (positiveCount) positiveCount.textContent = '0';
      positiveList.innerHTML = '<div class="empty-state">No positive signals found</div>';
    }
  }

  // Tech grid
  if (techGrid) {
    const f = data.features;
    const items = [
      { label: 'URL Length',       value: f.url_length + ' chars', cls: f.url_length > 100 ? 'bad' : f.url_length > 75 ? 'warn' : 'ok' },
      { label: 'Protocol',         value: f.uses_https ? 'HTTPS ✓' : 'HTTP ✗', cls: f.uses_https ? 'ok' : 'bad' },
      { label: 'TLD',              value: f.tld || '—', cls: '' },
      { label: 'Subdomain Depth',  value: f.subdomain_depth, cls: f.subdomain_depth >= 3 ? 'bad' : f.subdomain_depth >= 2 ? 'warn' : 'ok' },
      { label: 'Path Depth',       value: f.path_depth, cls: '' },
      { label: 'Domain Length',    value: f.domain_length + ' chars', cls: f.domain_length > 20 ? 'warn' : 'ok' },
      { label: 'Phishing Keywords',value: f.keyword_count + ' found', cls: f.keyword_count >= 3 ? 'bad' : f.keyword_count >= 1 ? 'warn' : 'ok' },
      { label: 'Analyzed At',      value: data.analyzed_at, cls: '' },
    ];
    techGrid.innerHTML = items.map(i => `
      <div class="tech-item">
        <div class="tech-label">${i.label}</div>
        <div class="tech-value ${i.cls}">${i.value}</div>
      </div>`).join('');
  }

  // SSL
  if (sslInfo) {
    const ssl = data.ssl;
    sslInfo.innerHTML = ssl.valid
      ? `<div class="positive-item">✓ Valid SSL Certificate</div>
         <div class="tech-item" style="margin-top:0.5rem">
           <div class="tech-label">Expires</div>
           <div class="tech-value ${ssl.days_remaining < 30 ? 'warn' : 'ok'}">${ssl.expiry || '—'} (${ssl.days_remaining} days)</div>
         </div>`
      : `<div class="risk-item medium" style="margin:0"><span class="risk-badge">warn</span> SSL certificate could not be verified</div>`;
  }

  // Domain age
  if (domainInfo) {
    const age = data.domain_age;
    domainInfo.innerHTML = (age.age_days !== null && age.age_days !== undefined)
      ? `<div class="tech-item"><div class="tech-label">Created</div>
           <div class="tech-value ${age.age_days < 30 ? 'bad' : age.age_days < 180 ? 'warn' : 'ok'}">${age.creation_date || '—'} (${age.age_days} days ago)</div></div>
         <div class="tech-item" style="margin-top:0.5rem"><div class="tech-label">Registrar</div>
           <div class="tech-value">${age.registrar || 'N/A'}</div></div>`
      : `<div class="empty-state">WHOIS data unavailable for this domain</div>`;
  }

  if (downloadReport) downloadReport.dataset.url = data.url;
}

// ── Score ring animation ──────────────────────────────────
function animateScore(target, color) {
  if (!ringFill || !scoreNum) return;
  const circumference = 201;
  ringFill.style.stroke = color;
  let current = 0;
  const step = target / 40;
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    scoreNum.textContent = Math.round(current);
    ringFill.style.strokeDashoffset = circumference - (current / 100) * circumference;
    if (current >= target) clearInterval(timer);
  }, 25);
}

// ── Download PDF ──────────────────────────────────────────
if (downloadReport) {
  downloadReport.addEventListener('click', async () => {
    const url = downloadReport.dataset.url;
    if (!url) return;
    downloadReport.textContent = '⏳ Generating…';
    downloadReport.disabled = true;
    try {
      const res = await fetch('/download-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!res.ok) throw new Error('Failed');
      const blob = await res.blob();
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = 'ThreatLens_Report.pdf';
      link.click();
    } catch (e) {
      showError('Could not generate report. Try again.');
    } finally {
      downloadReport.textContent = '📄 Download PDF Report';
      downloadReport.disabled = false;
    }
  });
}

// ── Analyze another ───────────────────────────────────────
if (analyzeAnother) {
  analyzeAnother.addEventListener('click', () => {
    if (resultSection) resultSection.classList.add('hidden');
    if (urlInput) urlInput.value = '';
    if (clearBtn) clearBtn.classList.remove('visible');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => urlInput && urlInput.focus(), 500);
  });
}

// ── Helpers ───────────────────────────────────────────────
function setLoading(state) {
  if (!analyzeBtn) return;
  analyzeBtn.disabled = state;
  const txt = analyzeBtn.querySelector('.btn-text');
  const ldr = analyzeBtn.querySelector('.btn-loader');
  if (txt) txt.classList.toggle('hidden', state);
  if (ldr) ldr.classList.toggle('hidden', !state);
}
function showError(msg) {
  if (!errorToast) return;
  if (errorMsg) errorMsg.textContent = msg;
  errorToast.classList.remove('hidden');
  setTimeout(() => errorToast.classList.add('hidden'), 5000);
}
function hideError() {
  if (errorToast) errorToast.classList.add('hidden');
}

// ── Scroll Reveal Observer ────────────────────────────────
(function() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

  function initReveal() {
    document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-stagger').forEach(el => {
      observer.observe(el);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initReveal);
  } else {
    initReveal();
  }
})();