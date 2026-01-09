let authToken = localStorage.getItem('authToken');
let currentUser = null;

// API调用包装
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json'
    };

    if (authToken && !endpoint.includes('/login')) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await fetch(endpoint, {
        ...options,
        headers: {
            ...headers,
            ...options.headers
        }
    });

    if (response.status === 401) {
        logout();
        throw new Error('未授权，请重新登录');
    }

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.detail || '请求失败');
    }

    return data;
}

// 登录处理
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const username = formData.get('username');
    const password = formData.get('password');
    const errorEl = document.getElementById('login-error');

    try {
        const data = await apiCall('/admin/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        showApp();
    } catch (error) {
        errorEl.textContent = error.message;
    }
});

function logout() {
    console.log('Logging out...');
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showLogin();
}

// 绑定事件监听器
function bindEvents() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.onclick = (e) => {
            e.preventDefault();
            logout();
        };
    }
}

// 页面加载时执行
document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    // 侧边栏导航
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            switchPage(page);
        });
    });
});

function showLogin() {
    const loginPage = document.getElementById('login-page');
    loginPage.style.setProperty('display', 'flex', 'important');
    loginPage.classList.add('active');

    const appPage = document.getElementById('app-page');
    appPage.style.setProperty('display', 'none', 'important');
    appPage.classList.remove('active');
}

function showApp() {
    if (!currentUser) return showLogin();

    document.getElementById('login-page').style.setProperty('display', 'none', 'important');
    document.getElementById('app-page').style.setProperty('display', 'block', 'important');

    const userDisplay = document.getElementById('current-user');
    if (userDisplay) userDisplay.textContent = currentUser.username;

    loadConnections();
}

function switchPage(page) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(page + '-content').classList.add('active');

    switch (page) {
        case 'connections': loadConnections(); break;
        case 'keys': loadKeys(); break;
        case 'audit': loadAuditLogs(); break;
    }
}

// ---------------- 业务逻辑 ----------------

// 1. 连接管理
async function loadConnections() {
    const tbody = document.getElementById('connections-table-body');
    if (!tbody) return;
    try {
        const data = await apiCall('/admin/connections');
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td><strong>${item.name}</strong></td>
                <td>${item.host}:${item.port}</td>
                <td><code>${item.database}</code></td>
                <td>${item.username} / ***</td>
                <td>${item.db_type}</td>
                <td>${item.description || '-'}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteConnection(${item.id})">删除</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8">加载失败: ${error.message}</td></tr>`;
    }
}

function showConnectionModal() {
    document.getElementById('modal-title').textContent = '添加数据库连接';
    document.getElementById('modal-body').innerHTML = `
        <form id="connection-form">
            <div class="form-group"><label>名称</label><input type="text" name="name" required placeholder="如：测试库"></div>
            <div class="form-group"><label>主机</label><input type="text" name="host" required></div>
            <div class="form-group"><label>端口</label><input type="number" name="port" value="3306" required></div>
            <div class="form-group">
                <label>类型</label>
                <select name="db_type"><option value="mysql">MySQL</option><option value="postgresql">PostgreSQL</option></select>
            </div>
            <div class="form-group"><label>数据库</label><input type="text" name="database" required></div>
            <div class="form-group"><label>用户名</label><input type="text" name="username" required></div>
            <div class="form-group"><label>密码</label><input type="password" name="password" required></div>
            <div class="form-group"><label>描述</label><textarea name="description"></textarea></div>
            <button type="submit" class="btn btn-primary">提交保存</button>
        </form>
    `;
    document.getElementById('connection-form').onsubmit = async (e) => {
        e.preventDefault();
        const params = new URLSearchParams(new FormData(e.target));
        try {
            await apiCall('/admin/connections?' + params, { method: 'POST' });
            closeModal();
            loadConnections();
        } catch (error) { alert(error.message); }
    };
    openModal();
}

async function deleteConnection(id) {
    if (confirm('确认删除此连接？')) {
        await apiCall(`/admin/connections/${id}`, { method: 'DELETE' });
        loadConnections();
    }
}

// 2. 访问密钥与权限管理 (并表展示)
async function loadKeys() {
    const tbody = document.getElementById('keys-table-body');
    if (!tbody) return;
    try {
        // 同时获取密钥、连接、权限三表数据
        const [keysRes, connsRes, permsRes] = await Promise.all([
            apiCall('/admin/keys'),
            apiCall('/admin/connections'),
            apiCall('/admin/permissions')
        ]);

        const connsMap = Object.fromEntries(connsRes.items.map(c => [c.id, c.name]));

        tbody.innerHTML = keysRes.items.map(key => {
            // 找出这个key对应的所有权限
            const myPerms = permsRes.items.filter(p => p.key_id === key.id);
            const permHtml = myPerms.map(p => `
                <div class="tag-item">
                    <span>${connsMap[p.connection_id] || '已移除'} (${p.select_only ? '只读' : '读写'})</span>
                    <span class="remove-icon" onclick="deletePermission(${p.id})">&times;</span>
                </div>
            `).join('');

            return `
                <tr>
                    <td>${key.id}</td>
                    <td><code>${key.ak}</code></td>
                    <td>${key.description || '-'}</td>
                    <td>${key.enabled ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-danger">禁用</span>'}</td>
                    <td class="permissions-cell">
                        <div class="tag-container">${permHtml}</div>
                        <button class="btn btn-xs btn-outline" onclick="showAddPermissionModal(${key.id})">+ 授权连接</button>
                    </td>
                    <td>${key.created_by || '-'}</td>
                    <td>${formatDate(key.created_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-danger" onclick="deleteKey(${key.id})">删除</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8">加载失败: ${error.message}</td></tr>`;
    }
}

function showKeyModal() {
    document.getElementById('modal-title').textContent = '创建访问密钥';
    document.getElementById('modal-body').innerHTML = `
        <form id="key-form">
            <div class="form-group"><label>AK (Access Key)</label><input type="text" name="ak" required placeholder="如：mcp_key_01"></div>
            <div class="form-group"><label>描述</label><input type="text" name="description" placeholder="如：给外部系统调用"></div>
            <button type="submit" class="btn btn-primary">创建</button>
        </form>
    `;
    document.getElementById('key-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        try {
            await apiCall('/admin/keys', {
                method: 'POST',
                body: JSON.stringify({ ak: fd.get('ak'), description: fd.get('description'), enabled: true })
            });
            closeModal();
            loadKeys();
        } catch (error) { alert(error.message); }
    };
    openModal();
}

async function deleteKey(id) {
    if (confirm('确认删除此密钥？相关权限也将被系统自动清理。')) {
        await apiCall(`/admin/keys/${id}`, { method: 'DELETE' });
        loadKeys();
    }
}

// 3. 关联权限弹窗（支持多选）
async function showAddPermissionModal(keyId) {
    const connsRes = await apiCall('/admin/connections');
    const permsRes = await apiCall('/admin/permissions');

    // 找出该密钥已授权的连接ID
    const existingConnIds = permsRes.items
        .filter(p => p.key_id === keyId)
        .map(p => p.connection_id);

    document.getElementById('modal-title').textContent = '为密钥分配权限（可多选）';
    document.getElementById('modal-body').innerHTML = `
        <form id="perm-form">
            <div class="form-group">
                <label>选择数据库连接（可多选）</label>
                <div style="max-height: 300px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px;">
                    ${connsRes.items.map(c => {
        const isExisting = existingConnIds.includes(c.id);
        return `
                            <div style="margin-bottom: 8px;">
                                <label style="display: flex; align-items: center; cursor: pointer;">
                                    <input type="checkbox" name="connection_ids" value="${c.id}" 
                                           ${isExisting ? 'checked disabled' : ''} 
                                           style="margin-right: 8px;">
                                    <span style="${isExisting ? 'color: #94a3b8;' : ''}">${c.name} (${c.host}:${c.port}) ${isExisting ? '✓ 已授权' : ''}</span>
                                </label>
                            </div>
                        `;
    }).join('')}
                </div>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="select_only" checked> 只读模式 (仅限查询)</label>
            </div>
            <button type="submit" class="btn btn-primary">确认授权</button>
        </form>
    `;

    document.getElementById('perm-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const selectedIds = fd.getAll('connection_ids');
        const selectOnly = fd.get('select_only') === 'on';

        if (selectedIds.length === 0) {
            alert('请至少选择一个连接');
            return;
        }

        try {
            // 批量创建权限
            for (const connId of selectedIds) {
                const params = new URLSearchParams({
                    key_id: keyId,
                    connection_id: connId,
                    select_only: selectOnly
                });
                await apiCall('/admin/permissions?' + params, { method: 'POST' });
            }
            closeModal();
            loadKeys();
        } catch (error) {
            alert('授权失败: ' + error.message);
        }
    };
    openModal();
}

async function deletePermission(id) {
    if (confirm('确认移除此授权连接？')) {
        await apiCall(`/admin/permissions/${id}`, { method: 'DELETE' });
        loadKeys();
    }
}

// 4. 审计日志
async function loadAuditLogs() {
    const tbody = document.getElementById('audit-table-body');
    const accessKey = document.getElementById('audit-filter-key').value;
    const operation = document.getElementById('audit-filter-operation').value;
    const params = new URLSearchParams({ limit: 50 });
    if (accessKey) params.append('access_key', accessKey);
    if (operation) params.append('operation', operation);

    try {
        const data = await apiCall('/admin/audit/logs?' + params);
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${formatDate(item.timestamp)}</td>
                <td><code>${item.access_key}</code></td>
                <td>${item.client_ip || '-'}</td>
                <td>${item.operation}</td>
                <td title="${item.sql_text || ''}">${(item.sql_text || '').substring(0, 30)}...</td>
                <td>${item.rows_affected || '-'}</td>
                <td>${item.duration_ms}ms</td>
                <td>${item.status === 'success' ? '✅' : '❌'}</td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8">加载异常</td></tr>`;
    }
}

// 模态框与工具
function openModal() { document.getElementById('modal-overlay').classList.add('active'); }
function closeModal() { document.getElementById('modal-overlay').classList.remove('active'); }
function formatDate(s) {
    if (!s) return '-';
    const d = new Date(s);
    return d.toLocaleString('zh-CN');
}

// 初始化
if (authToken) {
    apiCall('/admin/me').then(d => { currentUser = d.user; showApp(); }).catch(logout);
} else {
    showLogin();
}
