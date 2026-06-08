// === 主页逻辑 ===
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
const uploadProgress = document.getElementById('uploadProgress');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const fileGrid = document.getElementById('fileGrid');
const toast = document.getElementById('toast');

// 点击上传
uploadZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) uploadFile(e.target.files[0]);
});

// 拖拽上传
uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('dragover'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
});

function showToast(msg, type = 'success') {
    toast.textContent = msg;
    toast.className = 'toast ' + type;
    setTimeout(() => toast.classList.add('hidden'), 3000);
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/(1024*1024)).toFixed(1) + ' MB';
}

async function uploadFile(file) {
    uploadProgress.classList.remove('hidden');
    uploadZone.querySelector('.upload-icon').style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', 'api/upload.php');

    xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
            const pct = Math.round(e.loaded / e.total * 100);
            progressFill.style.width = pct + '%';
            progressText.textContent = `上传中... ${pct}%`;
        }
    };

    xhr.onload = () => {
        uploadProgress.classList.add('hidden');
        uploadZone.querySelector('.upload-icon').style.display = '';
        try {
            const resp = JSON.parse(xhr.responseText);
            if (resp.success) {
                showToast('✅ 上传成功！已解压 ' + resp.total_files + ' 个文件');
                loadFiles();
            } else {
                showToast('❌ ' + (resp.error || '上传失败'), 'error');
            }
        } catch {
            showToast('❌ 服务器错误', 'error');
        }
    };

    xhr.onerror = () => {
        uploadProgress.classList.add('hidden');
        showToast('❌ 网络错误', 'error');
    };

    xhr.send(formData);
}

async function loadFiles() {
    try {
        const resp = await fetch('api/files.php');
        const files = await resp.json();

        if (files.length === 0) {
            fileGrid.innerHTML = '<div class="empty-state">暂无文件，请上传</div>';
            return;
        }

        fileGrid.innerHTML = files.map(f => `
            <div class="file-card" data-id="${escapeAttr(f.id)}">
                <div class="card-icon">${f.extracted ? '📦' : '📄'}</div>
                <div class="card-info">
                    <div class="card-name">${escapeHtml(f.name)}</div>
                    <div class="card-meta">
                        <span>📏 ${formatSize(f.size)}</span>
                        ${f.extracted ? '<span>📁 ' + f.total_files + ' 个文件</span>' : ''}
                        ${f.extracted && f.text_files ? '<span>📝 ' + f.text_files + ' 个可分析</span>' : ''}
                    </div>
                    ${f.extracted ?
                        '<div class="card-extracted">✅ 已解压</div>' :
                        '<div class="card-extracted failed">⚠ 无法解压</div>'
                    }
                </div>
                <div class="card-actions">
                    ${f.extracted ? `<a href="analysis.html?id=${f.id}" class="card-btn">🔍 分析</a>` : ''}
                    <a href="api/download.php?id=${f.id}" class="card-download-btn" title="下载原始文件">⬇ 下载</a>
                    <button class="card-delete-btn" onclick="deleteFile('${escapeAttr(f.id)}', this)" title="删除">🗑</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        console.error('加载文件列表失败', e);
    }
}

async function deleteFile(id, btn) {
    if (!confirm('确定要删除这个文件及其解压内容吗？此操作不可恢复。')) return;
    
    btn.disabled = true;
    btn.textContent = '⏳';
    
    try {
        const resp = await fetch('api/delete.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        const data = await resp.json();
        if (data.success) {
            showToast('🗑 已删除');
            // 动画移除卡片
            const card = btn.closest('.file-card');
            card.style.transition = 'all 0.3s';
            card.style.opacity = '0';
            card.style.transform = 'translateX(30px)';
            setTimeout(() => loadFiles(), 300);
        } else {
            showToast('❌ ' + (data.error || '删除失败'), 'error');
            btn.disabled = false;
            btn.textContent = '🗑';
        }
    } catch (e) {
        showToast('❌ 网络错误', 'error');
        btn.disabled = false;
        btn.textContent = '🗑';
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// 初始加载
loadFiles();
