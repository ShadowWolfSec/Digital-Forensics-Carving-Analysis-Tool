function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}

function formatDuration(seconds) {
  if (!seconds || seconds <= 0 || !isFinite(seconds)) return "--:--:--";
  const totalSec = Math.round(seconds);
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  if (hrs > 0) {
    return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let _currentDriveTargetId = 'source_path';

async function openDriveModal(targetInputId) {
  _currentDriveTargetId = targetInputId || 'source_path';
  const modal = document.getElementById('driveModal');
  const container = document.getElementById('drivesContainer') || document.getElementById('drivesList');
  const status = document.getElementById('drivesStatus');
  if (!modal) return;
  modal.style.display = 'flex';
  if (container) container.innerHTML = '<div style="text-align:center; padding:20px; color:#6b7280;">Scanning system drives...</div>';
  if (status) status.textContent = 'Scanning system drives...';

  try {
    const res = await fetch('/api/drives');
    const data = await res.json();
    if (!data.ok || !data.drives || data.drives.length === 0) {
      const msg = 'No drives detected or permission denied.';
      if (status) status.textContent = msg;
      if (container) container.innerHTML = `<div style="padding:15px; color:#dc2626;">${msg}</div>`;
      return;
    }
    if (status) status.textContent = `Found ${data.drives.length} drives and partitions. Click any drive to select it:`;
    if (container) {
      container.innerHTML = '';
      data.drives.forEach(d => {
        const div = document.createElement('div');
        div.className = 'drive-item';
        const badgeClass = d.accessible ? 'badge-ok' : 'badge-admin';
        const badgeText = d.accessible ? 'Ready' : (d.size_human || 'Admin Required');
        div.innerHTML = `
          <div style="flex:1;">
            <div class="drive-id" style="font-weight:700; color:#111827;">${d.id}</div>
            <div class="drive-desc" style="font-size:12px; color:#6b7280;">${d.display || d.caption || ''}</div>
          </div>
          <div><span class="badge ${badgeClass}">${badgeText}</span></div>
        `;
        div.onclick = () => {
          const input = document.getElementById(_currentDriveTargetId);
          if (input) input.value = d.id;
          const st = document.getElementById('source_type');
          if (st && (d.kind === 'physical_drive' || d.kind === 'logical_volume')) {
            st.value = 'physical_drive';
          }
          if (typeof saveState === 'function') saveState();
          closeDriveModal();
        };
        container.appendChild(div);
      });
    }
  } catch (err) {
    if (status) status.textContent = 'Error detecting drives: ' + err;
    if (container) container.innerHTML = '<div style="padding:15px; color:#dc2626;">Error: ' + err + '</div>';
  }
}

function closeDriveModal() {
  const modal = document.getElementById('driveModal');
  if (modal) modal.style.display = 'none';
}

async function pickPath(targetId, kind, title) {
  const input = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
  const initial = input ? (input.value || "") : "";
  try {
    const res = await fetch(`/api/pick-path?kind=${encodeURIComponent(kind || 'file')}&title=${encodeURIComponent(title || '')}&initial=${encodeURIComponent(initial)}`);
    const data = await res.json();
    if (data.ok && data.path && input) {
      input.value = data.path;
      if (typeof window.onPathPicked === 'function') {
        window.onPathPicked(targetId, data.path);
      }
      if (typeof saveState === 'function') {
        saveState();
      }
    }
  } catch (e) {
    console.error("Path picker error:", e);
  }
}

window.addEventListener('click', (e) => {
  const modal = document.getElementById('driveModal');
  if (modal && e.target === modal) closeDriveModal();
});

