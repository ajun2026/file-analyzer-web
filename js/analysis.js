// === 分析页面逻辑 ===
const urlParams = new URLSearchParams(window.location.search);
const fileId = urlParams.get('id');

if (!fileId) {
    document.body.innerHTML = '<div style="text-align:center;padding:60px;"><h2>缺少文件 ID</h2><a href="/">返回首页</a></div>';
    throw new Error('No file ID');
}

// DOM 引用
const fileTree = document.getElementById('fileTree');
const viewerTitle = document.getElementById('viewerTitle');
const viewerInfo = document.getElementById('viewerInfo');
const viewerContent = document.getElementById('viewerContent');
const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
const resizer = document.getElementById('resizer');
const hResizer = document.getElementById('hResizer');
const filePanel = document.getElementById('filePanel');
const chatPanel = document.querySelector('.chat-panel');

// 状态
let chatHistory = [];
let isLoading = false;

// ========== 文件树 ==========
async function loadFileTree() {
    try {
        const resp = await fetch('api/filetree.php?id=' + fileId);
        const tree = await resp.json();
        if (tree.error) {
            fileTree.innerHTML = '<div class="loading">加载失败: ' + tree.error + '</div>';
            return;
        }
        fileTree.innerHTML = renderTree(tree);
        bindTreeEvents();
    } catch (e) {
        fileTree.innerHTML = '<div class="loading">加载失败</div>';
    }
}

function renderTree(items) {
    let html = '';
    for (const item of items) {
        if (item.type === 'dir') {
            html += `<div class="tree-item tree-dir" data-path="${escapeAttr(item.path)}">
                <span class="icon">📁</span><span class="name">${escapeHtml(item.name)}</span>
            </div>`;
            html += `<div class="tree-children">${renderTree(item.children || [])}</div>`;
        } else {
            const cls = item.readable ? 'tree-file' : 'tree-file not-readable';
            html += `<div class="tree-item ${cls}" data-path="${escapeAttr(item.path)}" data-readable="${item.readable}">
                <span class="icon">${getFileIcon(item.name)}</span><span class="name">${escapeHtml(item.name)}</span>
            </div>`;
        }
    }
    return html;
}

function getFileIcon(name) {
    const ext = name.split('.').pop().toLowerCase();
    const icons = { js: '🟨', ts: '🟦', py: '🐍', php: '🐘', html: '🌐', css: '🎨', json: '📋',
        xml: '📰', yaml: '⚙️', yml: '⚙️', md: '📝', txt: '📄', log: '📜', sql: '🗄️',
        sh: '💻', bash: '💻', env: '🔧', cfg: '⚙️', ini: '⚙️', toml: '⚙️', dockerfile: '🐳' };
    return icons[ext] || '📄';
}

function bindTreeEvents() {
    document.querySelectorAll('.tree-item.tree-dir').forEach(el => {
        el.addEventListener('click', (e) => {
            e.stopPropagation();
            const children = el.nextElementSibling;
            if (children && children.classList.contains('tree-children')) {
                children.classList.toggle('collapsed');
                el.querySelector('.icon').textContent = children.classList.contains('collapsed') ? '📁' : '📂';
            }
        });
    });

    document.querySelectorAll('.tree-item.tree-file[data-readable="true"]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.stopPropagation();
            const path = el.dataset.path;
            loadFileContent(path, el);
        });
    });
}

async function loadFileContent(filePath, el) {
    // 标记激活
    document.querySelectorAll('.tree-item.active').forEach(e => e.classList.remove('active'));
    if (el) el.classList.add('active');

    viewerTitle.textContent = filePath.split('/').pop();
    viewerContent.innerHTML = '<div style="text-align:center;color:#999;padding:30px;">加载中...</div>';

    try {
        const resp = await fetch('api/read.php?id=' + fileId + '&file=' + encodeURIComponent(filePath));
        const data = await resp.json();
        if (data.error) {
            viewerContent.innerHTML = '<div class="viewer-placeholder">⚠ ' + data.error + '</div>';
            return;
        }
        viewerInfo.textContent = formatSize(data.size);
        const lang = getLanguage(filePath);
        viewerContent.innerHTML = `<pre><code class="language-${lang}">${escapeHtml(data.content)}</code></pre>`;
    } catch (e) {
        viewerContent.innerHTML = '<div class="viewer-placeholder">⚠ 加载失败</div>';
    }
}

function getLanguage(filePath) {
    const ext = filePath.split('.').pop().toLowerCase();
    const map = { js: 'javascript', ts: 'typescript', py: 'python', php: 'php', html: 'html',
        css: 'css', json: 'json', xml: 'xml', yaml: 'yaml', yml: 'yaml', md: 'markdown',
        sh: 'bash', bash: 'bash', sql: 'sql', toml: 'toml', ini: 'ini', cfg: 'ini' };
    return map[ext] || 'plaintext';
}

// ========== AI 对话 ==========
chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
sendBtn.addEventListener('click', sendMessage);

async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text || isLoading) return;

    chatInput.value = '';
    chatInput.style.height = 'auto';
    sendBtn.disabled = true;
    isLoading = true;

    // 添加用户消息
    appendMessage('user', text);
    chatHistory.push({ role: 'user', content: text });

    // 添加 AI 占位
    const msgDiv = appendMessage('assistant', '', true);
    const contentDiv = msgDiv.querySelector('.msg-content');

    // 调用 SSE 流式 API
    try {
        const resp = await fetch('api/chat.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: fileId,
                message: text,
                history: chatHistory.slice(0, -1)
            })
        });

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let fullContent = '';
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed || !trimmed.startsWith('data: ')) continue;

                const jsonStr = trimmed.slice(6);
                if (jsonStr === '[DONE]') break;

                try {
                    const data = JSON.parse(jsonStr);
                    if (data.error) {
                        fullContent = '❌ 错误: ' + data.error;
                        break;
                    }
                    if (data.content) {
                        fullContent += data.content;
                        contentDiv.innerHTML = renderMarkdown(fullContent);
                        chatMessages.scrollTop = chatMessages.scrollHeight;
                    }
                } catch (e) {}
            }
        }

        if (!fullContent) fullContent = '(AI 未返回内容)';
        contentDiv.innerHTML = renderMarkdown(fullContent);
        chatHistory.push({ role: 'assistant', content: fullContent });

    } catch (e) {
        contentDiv.innerHTML = '❌ 网络错误: ' + e.message;
        chatHistory.push({ role: 'assistant', content: '网络错误' });
    }

    isLoading = false;
    sendBtn.disabled = false;
    chatInput.focus();
    chatMessages.scrollTop = chatMessages.scrollHeight;
    // 自动保存聊天记录
    saveHistory();
}

function appendMessage(role, content, isStreaming = false) {
    // 移除 loading 指示器
    const existingLoading = chatMessages.querySelector('.chat-loading');
    if (existingLoading) existingLoading.remove();

    const div = document.createElement('div');
    div.className = 'chat-msg ' + role;
    div.innerHTML = `
        <div class="msg-role">${role === 'user' ? '👤 你' : '🤖 AI 助手'}</div>
        <div class="msg-content">${isStreaming ? '<div class="chat-loading"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>' : renderMarkdown(content)}</div>
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return div;
}

// 简单的 Markdown 渲染
function renderMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    // 代码块
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>');
    // 行内代码
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    // 粗体
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    // 标题
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    // 无序列表
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    // 换行
    html = html.replace(/\n\n/g, '</p><p>');
    html = html.replace(/\n/g, '<br>');
    html = '<p>' + html + '</p>';
    return html;
}

// ========== 拖拽分隔线 ==========
let isResizing = false;
resizer.addEventListener('mousedown', (e) => {
    isResizing = true;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
});
document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;
    const width = Math.max(180, Math.min(500, e.clientX));
    filePanel.style.width = width + 'px';
});
document.addEventListener('mouseup', () => {
    if (isResizing) {
        isResizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    }
    if (isHResizing) {
        isHResizing = false;
        hResizer.classList.remove('active');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    }
});

// ========== 水平拖拽（上下拉对话框） ==========
let isHResizing = false;
hResizer.addEventListener('mousedown', (e) => {
    isHResizing = true;
    hResizer.classList.add('active');
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
});
document.addEventListener('mousemove', (e) => {
    if (!isHResizing) return;
    const mainRect = document.querySelector('.main-panel').getBoundingClientRect();
    const height = mainRect.bottom - e.clientY;
    chatPanel.style.height = Math.max(150, Math.min(height - 10, mainRect.height - 50)) + 'px';
});

// ========== 聊天记录持久化 ==========
async function loadHistory() {
    try {
        const resp = await fetch('api/chat_history.php?action=load&id=' + fileId);
        const data = await resp.json();
        if (data.messages && data.messages.length > 0) {
            chatHistory = data.messages;
            // 恢复 UI
            const welcome = chatMessages.querySelector('.chat-welcome');
            if (welcome) welcome.remove();
            for (const msg of chatHistory) {
                appendMessage(msg.role, msg.content);
            }
        }
    } catch (e) {
        console.log('加载聊天记录失败:', e);
    }
}

async function saveHistory() {
    try {
        await fetch('api/chat_history.php?action=save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: fileId, messages: chatHistory })
        });
    } catch (e) {
        console.log('保存聊天记录失败:', e);
    }
}

async function clearHistory() {
    chatHistory = [];
    chatMessages.innerHTML = `<div class="chat-welcome">
        <p>👋 你好！我是 AI 文件分析助手。</p>
        <p>我已经读取了你上传的所有文件内容，你可以问我任何关于这些文件的问题。</p>
    </div>`;
    try {
        await fetch('api/chat_history.php?action=clear&id=' + fileId);
    } catch (e) {}
}

// ========== 工具函数 ==========
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/(1024*1024)).toFixed(1) + ' MB';
}
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
function escapeAttr(str) {
    return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// 自动调整输入框高度
chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 100) + 'px';
});

// 启动
loadFileTree();
loadHistory();

// 清除聊天记录按钮
const clearChatBtn = document.getElementById('clearChatBtn');
if (clearChatBtn) {
    clearChatBtn.addEventListener('click', () => {
        if (chatHistory.length === 0) return;
        if (confirm('确定要清除当前聊天记录吗？')) {
            clearHistory();
        }
    });
}
