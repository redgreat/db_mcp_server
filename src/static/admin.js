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
        case 'audit':
            // 默认加载数据库操作日志
            switchLogTab('audit');
            break;
    }
}

// ---------------- 业务逻辑 ----------------

// 1. 连接管理（支持分页）
let currentConnectionsPage = 1;
const connectionsPageSize = 10;

async function loadConnections(page = 1) {
    currentConnectionsPage = page;
    const tbody = document.getElementById('connections-table-body');
    if (!tbody) return;

    const params = new URLSearchParams({ page, page_size: connectionsPageSize });

    try {
        const data = await apiCall('/admin/connections?' + params);
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

        // 渲染分页器
        renderPagination('connections-pagination', data.total, data.page, data.page_size, loadConnections);
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

// 2. 访问密钥与权限管理（支持分页）
let currentKeysPage = 1;
const keysPageSize = 10;

async function loadKeys(page = 1) {
    currentKeysPage = page;
    const tbody = document.getElementById('keys-table-body');
    if (!tbody) return;

    const params = new URLSearchParams({ page, page_size: keysPageSize });

    try {
        // 同时获取密钥、连接、权限、白名单四表数据
        const [keysRes, connsRes, permsRes, whitelistRes] = await Promise.all([
            apiCall('/admin/keys?' + params),
            apiCall('/admin/connections'),  // 连接需要全量，用于显示名称
            apiCall('/admin/permissions'),
            apiCall('/admin/whitelist')
        ]);

        const connsMap = Object.fromEntries(connsRes.items.map(c => [c.id, c.name]));

        tbody.innerHTML = keysRes.items.map(key => {
            // 找出这个key对应的所有权限
            const myPerms = permsRes.items.filter(p => p.key_id === key.id);
            const permHtml = myPerms.map(p => {
                let permText = connsMap[p.connection_id] || '已移除';
                let permBadges = [];

                if (p.select_only) {
                    permBadges.push('只读');
                } else {
                    permBadges.push('读写');
                    if (p.allow_ddl) {
                        permBadges.push('DDL');
                    }
                }

                return `
                    <div class="tag-item">
                        <span>${permText} (${permBadges.join(' + ')})</span>
                        <span class="remove-icon" onclick="deletePermission(${p.id})">&times;</span>
                    </div>
                `;
            }).join('');

            // 找出这个key对应的所有白名单
            const myWhitelist = whitelistRes.items.filter(w => w.key_id === key.id);
            const whitelistHtml = myWhitelist.map(w => `
                <div class="tag-item">
                    <span>${w.cidr}${w.description ? ' (' + w.description + ')' : ''}</span>
                    <span class="remove-icon" onclick="deleteWhitelist(${w.id})">&times;</span>
                </div>
            `).join('');

            return `
                <tr>
                    <td>${key.id}</td>
                    <td><code>${key.ak}</code></td>
                    <td>${key.description || '-'}</td>
                    <td>
                        <span class="badge ${key.enabled ? 'badge-success' : 'badge-danger'}" 
                              style="cursor: pointer;" 
                              onclick="toggleKeyStatus(${key.id}, ${!key.enabled})"
                              title="点击切换状态">
                            ${key.enabled ? '✓ 启用' : '✗ 禁用'}
                        </span>
                    </td>
                    <td class="permissions-cell">
                        <div class="tag-container">${permHtml}</div>
                        <button class="btn btn-xs btn-outline" onclick="showAddPermissionModal(${key.id})">+ 授权连接</button>
                    </td>
                    <td class="permissions-cell">
                        <div class="tag-container">${whitelistHtml}</div>
                        <button class="btn btn-xs btn-outline" onclick="showAddWhitelistModal(${key.id})">+ 添加IP</button>
                    </td>
                    <td>${key.created_by || '-'}</td>
                    <td>${formatDate(key.created_at)}</td>
                    <td>
                        <button class="btn btn-sm ${key.enabled ? 'btn-outline' : 'btn-success'}" 
                                onclick="toggleKeyStatus(${key.id}, ${!key.enabled})" 
                                style="margin-right: 4px;">
                            ${key.enabled ? '禁用' : '启用'}
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteKey(${key.id})">删除</button>
                    </td>
                </tr>
            `;
        }).join('');

        // 渲染分页器
        renderPagination('keys-pagination', keysRes.total, keysRes.page, keysRes.page_size, loadKeys);
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="9">加载失败: ${error.message}</td></tr>`;
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

async function toggleKeyStatus(id, enabled) {
    try {
        await apiCall(`/admin/keys/${id}/toggle`, {
            method: 'PATCH',
            body: JSON.stringify({ enabled })
        });
        loadKeys();
    } catch (error) {
        alert('状态切换失败: ' + error.message);
    }
}

// 3. 关联权限弹窗（为每个连接单独配置权限）
async function showAddPermissionModal(keyId) {
    const connsRes = await apiCall('/admin/connections');
    const permsRes = await apiCall('/admin/permissions');

    // 找出该密钥已授权的连接ID
    const existingConnIds = permsRes.items
        .filter(p => p.key_id === keyId)
        .map(p => p.connection_id);

    // 过滤掉已授权的连接
    const availableConns = connsRes.items.filter(c => !existingConnIds.includes(c.id));

    document.getElementById('modal-title').textContent = '为密钥分配权限';
    document.getElementById('modal-body').innerHTML = `
        <form id="perm-form">
            <div class="form-group">
                <label>选择数据库连接并配置权限</label>
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px;" id="connections-list">
                    ${availableConns.length > 0 ? availableConns.map(c => `
                        <div style="margin-bottom: 12px; padding: 12px; border: 1px solid #e2e8f0; border-radius: 6px; background: #f8fafc;">
                            <div style="margin-bottom: 8px;">
                                <label style="display: flex; align-items: center; cursor: pointer; font-weight: 500;">
                                    <input type="checkbox" class="conn-checkbox" value="${c.id}" style="margin-right: 8px;" onchange="togglePermOptions(${c.id})">
                                    <div>
                                        <div>${c.name}</div>
                                        <div style="font-size: 12px; color: #64748b; font-weight: normal;">${c.host}:${c.port} / ${c.database}</div>
                                    </div>
                                </label>
                            </div>
                            <div id="perm-options-${c.id}" style="display: none; margin-left: 24px; padding-left: 12px; border-left: 2px solid #e2e8f0;">
                                <label style="display: block; margin-bottom: 4px; font-size: 13px;">
                                    <input type="radio" name="perm-type-${c.id}" value="readonly" checked style="margin-right: 6px;">
                                    只读 (仅 SELECT 查询)
                                </label>
                                <label style="display: block; margin-bottom: 4px; font-size: 13px;">
                                    <input type="radio" name="perm-type-${c.id}" value="readwrite" style="margin-right: 6px;">
                                    读写 (SELECT + INSERT/UPDATE/DELETE)
                                </label>
                                <label style="display: block; font-size: 13px;">
                                    <input type="radio" name="perm-type-${c.id}" value="full" style="margin-right: 6px;">
                                    完全权限 (包括 DDL: CREATE/DROP/ALTER)
                                </label>
                            </div>
                        </div>
                    `).join('') : '<div style="text-align: center; padding: 20px; color: #64748b;">所有连接都已授权</div>'}
                </div>
            </div>
            ${availableConns.length > 0 ? '<button type="submit" class="btn btn-primary">确认授权</button>' : ''}
        </form>
    `;

    // 切换权限选项显示
    window.togglePermOptions = (connId) => {
        const checkbox = document.querySelector(`input.conn-checkbox[value="${connId}"]`);
        const options = document.getElementById(`perm-options-${connId}`);
        if (checkbox.checked) {
            options.style.display = 'block';
        } else {
            options.style.display = 'none';
        }
    };

    document.getElementById('perm-form').onsubmit = async (e) => {
        e.preventDefault();

        // 获取所有选中的连接
        const selectedCheckboxes = document.querySelectorAll('input.conn-checkbox:checked');

        if (selectedCheckboxes.length === 0) {
            alert('请至少选择一个连接');
            return;
        }

        try {
            // 为每个选中的连接创建权限
            for (const checkbox of selectedCheckboxes) {
                const connId = checkbox.value;
                const permType = document.querySelector(`input[name="perm-type-${connId}"]:checked`).value;

                let selectOnly = true;
                let allowDdl = false;

                if (permType === 'readwrite') {
                    selectOnly = false;
                    allowDdl = false;
                } else if (permType === 'full') {
                    selectOnly = false;
                    allowDdl = true;
                }

                const params = new URLSearchParams({
                    key_id: keyId,
                    connection_id: connId,
                    select_only: selectOnly,
                    allow_ddl: allowDdl
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

// 白名单管理
async function showAddWhitelistModal(keyId) {
    document.getElementById('modal-title').textContent = '添加 IP 白名单';
    document.getElementById('modal-body').innerHTML = `
        <form id="whitelist-form">
            <div class="form-group">
                <label>IP 地址或 CIDR</label>
                <input type="text" name="cidr" required placeholder="如：192.168.1.100 或 192.168.1.0/24">
                <small style="color: #64748b; display: block; margin-top: 4px;">
                    支持单个 IP 或 CIDR 格式。0.0.0.0/0 表示允许所有 IP（不推荐）
                </small>
            </div>
            <div class="form-group">
                <label>描述（可选）</label>
                <input type="text" name="description" placeholder="如：办公室网络">
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
        </form>
    `;

    document.getElementById('whitelist-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const params = new URLSearchParams({
            key_id: keyId,
            cidr: fd.get('cidr'),
            description: fd.get('description') || ''
        });

        try {
            await apiCall('/admin/whitelist?' + params, { method: 'POST' });
            closeModal();
            loadKeys();
        } catch (error) {
            alert('添加失败: ' + error.message);
        }
    };
    openModal();
}

async function deleteWhitelist(id) {
    if (confirm('确认删除此 IP 白名单规则？')) {
        await apiCall(`/admin/whitelist/${id}`, { method: 'DELETE' });
        loadKeys();
    }
}

// 4. 审计日志（支持分页）
let currentAuditPage = 1;
const auditPageSize = 10;

async function loadAuditLogs(page = 1) {
    currentAuditPage = page;
    const tbody = document.getElementById('audit-table-body');
    const accessKey = document.getElementById('audit-filter-key').value;
    const operation = document.getElementById('audit-filter-operation').value;
    const params = new URLSearchParams({ page, page_size: auditPageSize });
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

        // 渲染分页器
        renderPagination('audit-pagination', data.total, data.page, data.page_size, loadAuditLogs);
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8">加载异常: ${error.message}</td></tr>`;
    }
}

// 5. 系统操作日志（支持分页）
let currentSystemPage = 1;
const systemPageSize = 20;

async function loadSystemLogs(page = 1) {
    currentSystemPage = page;
    const tbody = document.getElementById('system-table-body');
    const operation = document.getElementById('system-filter-operation').value;
    const resourceType = document.getElementById('system-filter-resource').value;
    const params = new URLSearchParams({ page, page_size: systemPageSize });
    if (operation) params.append('operation', operation);
    if (resourceType) params.append('resource_type', resourceType);

    try {
        const data = await apiCall('/admin/system/logs?' + params);
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${formatDate(item.timestamp)}</td>
                <td>${item.username || '-'}</td>
                <td>${item.operation}</td>
                <td>${item.resource_type}</td>
                <td>${item.resource_id || '-'}</td>
                <td title="${JSON.stringify(item.details || {})}">${JSON.stringify(item.details || {}).substring(0, 50)}...</td>
                <td>${item.client_ip || '-'}</td>
            </tr>
        `).join('');

        // 渲染分页器
        renderPagination('system-pagination', data.total, data.page, data.page_size, loadSystemLogs);
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7">加载异常: ${error.message}</td></tr>`;
    }
}

// Tab 切换
function switchLogTab(tab) {
    // 切换 Tab 按钮样式
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });

    // 切换内容显示
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(tab + '-tab-content').classList.add('active');

    // 加载对应数据
    if (tab === 'audit') {
        loadAuditLogs(1);
    } else if (tab === 'system') {
        loadSystemLogs(1);
    }
}

// 通用分页渲染函数
function renderPagination(elementId, total, currentPage, pageSize, loadFunc) {
    const container = document.getElementById(elementId);
    if (!container) return;

    const totalPages = Math.ceil(total / pageSize);
    if (totalPages <= 1) {
        container.innerHTML = `<div style="text-align: center; color: #64748b;">共 ${total} 条记录</div>`;
        return;
    }

    let html = `<div style="display: flex; align-items: center; justify-content: center; gap: 8px;">`;
    html += `<span style="color: #64748b; margin-right: 12px;">共 ${total} 条</span>`;

    // 上一页
    if (currentPage > 1) {
        html += `<button class="btn btn-sm btn-outline" onclick="${loadFunc.name}(${currentPage - 1})">上一页</button>`;
    }

    // 页码
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    for (let i = startPage; i <= endPage; i++) {
        if (i === currentPage) {
            html += `<button class="btn btn-sm btn-primary">${i}</button>`;
        } else {
            html += `<button class="btn btn-sm btn-outline" onclick="${loadFunc.name}(${i})">${i}</button>`;
        }
    }

    // 下一页
    if (currentPage < totalPages) {
        html += `<button class="btn btn-sm btn-outline" onclick="${loadFunc.name}(${currentPage + 1})">下一页</button>`;
    }

    html += `</div>`;
    container.innerHTML = html;
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
