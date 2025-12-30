// Enhanced UI: file preview, progress, pretty render of results
const form = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');
const fileDrop = document.getElementById('fileDrop');
const fileInfo = document.getElementById('fileInfo');
const fileNameEl = document.getElementById('fileName');
const fileSizeEl = document.getElementById('fileSize');
const fileTypeEl = document.getElementById('fileType');

const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');

const progressWrap = document.getElementById('progressWrap');
const progressBar = document.getElementById('progressBar');
const progressNote = document.getElementById('progressNote');

const resultsSection = document.getElementById('results');
const yaraContent = document.getElementById('yaraContent');
const vtContent = document.getElementById('vtContent');
const jsonOutput = document.getElementById('jsonOutput');

let selectedFile = null;

function humanFileSize(size) {
  if (size === 0) return '0 B';
  const i = Math.floor(Math.log(size) / Math.log(1024));
  const units = ['B','KB','MB','GB','TB'];
  return (size / Math.pow(1024, i)).toFixed(i ? 2 : 0) + ' ' + units[i];
}

// drag & drop UI (visual only)
fileDrop.addEventListener('dragover', (e)=>{ e.preventDefault(); fileDrop.style.opacity = 0.9; });
fileDrop.addEventListener('dragleave', ()=>{ fileDrop.style.opacity = 1; });
fileDrop.addEventListener('drop', (e)=>{ e.preventDefault(); fileDrop.style.opacity = 1; if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; handleFileSelect(); } });

fileInput.addEventListener('change', handleFileSelect);

function handleFileSelect() {
  if (!fileInput.files || !fileInput.files[0]) return;
  selectedFile = fileInput.files[0];
  fileNameEl.textContent = selectedFile.name;
  fileSizeEl.textContent = humanFileSize(selectedFile.size);
  fileTypeEl.textContent = selectedFile.type || 'n/a';
  fileInfo.style.display = 'block';
}

clearBtn.addEventListener('click', (e)=>{
  e.preventDefault();
  selectedFile = null;
  fileInput.value = '';
  fileInfo.style.display = 'none';
  resultsSection.style.display = 'none';
  progressWrap.style.display = 'none';
  progressBar.style.width = '0%';
  jsonOutput.textContent = '';
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!fileInput.files || !fileInput.files[0]) return alert('Please select a file first.');

  selectedFile = fileInput.files[0];

  // UI: show progress
  progressWrap.style.display = 'block';
  progressBar.style.width = '10%';
  progressNote.textContent = 'Uploading file...';

  // Assemble form data
  const fd = new FormData();
  fd.append('file', selectedFile);

  try {
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';

    // Use fetch for upload & response
    const resp = await fetch('/upload', {
      method: 'POST',
      body: fd
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Server returned ${resp.status}: ${errText}`);
    }

    // simulate progress update
    progressBar.style.width = '40%';
    progressNote.textContent = 'Waiting for analysis...';

    const data = await resp.json();

    // update UI with results
    progressBar.style.width = '100%';
    progressNote.textContent = 'Done';

    renderResults(data);
  } catch (err) {
    progressNote.textContent = 'Error';
    alert('Error: ' + err.message);
    jsonOutput.textContent = '';
    yaraContent.innerHTML = '<div class="muted small">Error during scan. Check console for details.</div>';
    vtContent.innerHTML = '<div class="muted small">Error during scan.</div>';
    console.error(err);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Upload & Scan';
  }
});

function renderResults(data) {
  resultsSection.style.display = 'block';

  // YARA
  try {
    const yara = data.yara_matches || [];
    if (yara.length === 0) {
      yaraContent.innerHTML = '<div class="muted small">No YARA matches.</div>';
    } else {
      yaraContent.innerHTML = '';
      yara.forEach(m => {
        const el = document.createElement('div');
        el.className = 'yara-match';
        el.innerHTML = `
          <div>
            <div class="yara-badge">${escapeHtml(m.rule_name || m.rule || 'unknown')}</div>
            <div class="muted small">${Object.keys(m.meta || {}).length ? 'meta: '+ JSON.stringify(m.meta) : ''}</div>
          </div>
          <div class="muted small">tags: ${Array.from(m.tags || []).join(', ')}</div>
        `;
        yaraContent.appendChild(el);
      });
    }
  } catch (e) {
    yaraContent.innerHTML = '<div class="muted small">Error rendering YARA results</div>';
  }

  // VirusTotal
  try {
    const vt = data.vt_report;
    if (!vt) {
      vtContent.innerHTML = '<div class="muted small">No VirusTotal report available (API key missing or file not found).</div>';
    } else {
      // Pretty parse common VT response shapes (file lookup or analysis)
      vtContent.innerHTML = '';
      const stats = vt.data && vt.data.attributes && vt.data.attributes.last_analysis_stats;
      if (stats) {
        const statEl = document.createElement('div');
        statEl.innerHTML = `<div><strong>Summary</strong></div>
          <div class="muted small">malicious: ${stats.malicious || 0} — suspicious: ${stats.suspicious || 0} — harmless: ${stats.harmless || 0}</div>`;
        vtContent.appendChild(statEl);
      }

      // If the engines details exist, show a condensed table
      const engines = (vt.data && vt.data.attributes && vt.data.attributes.last_analysis_results) || (vt.meta && vt.meta.file_info && vt.meta.file_info.scans);
      if (engines && typeof engines === 'object') {
        const tableWrap = document.createElement('div');
        tableWrap.style.maxHeight = '220px';
        tableWrap.style.overflow = 'auto';
        tableWrap.style.marginTop = '8px';

        const table = document.createElement('table');
        table.style.width = '100%';
        table.style.borderSpacing = '0 8px';
        table.innerHTML = `<thead><tr><th style="text-align:left">Engine</th><th style="text-align:left">Result</th></tr></thead><tbody></tbody>`;
        const tbody = table.querySelector('tbody');

        // engines may be either {engineName: {category, result}} or similar
        Object.keys(engines).slice(0, 200).forEach(name=>{
          const info = engines[name];
          let result = '';
          if (info && typeof info === 'object') {
            result = info.result || info.category || JSON.stringify(info);
          } else {
            result = String(info);
          }
          const tr = document.createElement('tr');
          tr.innerHTML = `<td style="padding:6px 8px;border-bottom:1px solid rgba(15,23,36,0.03)">${escapeHtml(name)}</td><td style="padding:6px 8px;border-bottom:1px solid rgba(15,23,36,0.03)">${escapeHtml(result || '')}</td>`;
          tbody.appendChild(tr);
        });

        tableWrap.appendChild(table);
        vtContent.appendChild(tableWrap);
      } else {
        vtContent.innerHTML += '<div class="muted small">No engine-level analysis details available.</div>';
      }
    }
  } catch (e) {
    vtContent.innerHTML = '<div class="muted small">Error rendering VirusTotal results</div>';
  }

  // Raw JSON pretty-print
  try {
    jsonOutput.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    jsonOutput.textContent = 'Unable to display JSON';
  }
}

// basic html escaping
function escapeHtml(s){
  if(!s) return '';
  return String(s).replace(/[&<>"']/g, (m) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]));
}
