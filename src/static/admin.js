// 全局变量
let authToken = localStorage.getItem('authToken');
let currentUser = null;

// API基础URL
const API_BASE = '';

// 工具函数
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (authToken && !endpoint.includes('/login')) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    try {
        const response = await fetch(API_BASE + endpoint, {
            ...options,
            headers
        });
        
        if (response.status === 401) {
            logout();
            throw new Error('未授权，请重新登录');
        }
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || '请求失败');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

function showError(message) {
    alert('错误: ' + message);
}

function showSuccess(message) {
    alert(message);
}

// 登录相关
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('login-error');
    
    try {
        const data = await apiCall('/admin/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        currentUser = data.user;
        
        showApp();
    } catch (error) {
        errorEl.textContent = error.message;
    }
});

document.getElementById('logout-btn')?.addEventListener('click', () => {
    logout();
});

function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showLogin();
}

function showLogin() {
    document.getElementById('login-page').classList.add('active');
    document.getElementById('app-page').classList.remove('active');
}

function showApp() {
    document.getElementById('login-page').classList.remove('active');
    document.getElementById('app-page').classList.add('active');
    document.getElementById('current-user').textContent = currentUser.username;
    loadInstances();
}

// 页面导航
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        switchPage(page);
    });
});

function switchPage(page) {
    // 更新菜单active状态
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // 更新内容区active状态
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(page + '-content').classList.add('active');
    
    // 加载对应数据
    switch(page) {
        case 'instances': loadInstances(); break;
        case 'databases': loadDatabases(); break;
        case 'accounts': loadAccounts(); break;
        case 'keys': loadKeys(); break;
        case 'permissions': loadPermissions(); break;
        case 'audit': loadAuditLogs(); break;
    }
}

// 实例管理
async function loadInstances() {
    const tbody = document.getElementById('instances-table-body');
    try {
        const data = await apiCall('/admin/instances');
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td>${item.name}</td>
                <td>${item.host}</td>
                <td>${item.port}</td>
                <td><span class="badge badge-success">${item.db_type}</span></td>
                <td>${item.description ||'-'}</td>
                <td>${formatDate(item.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteInstance(${item.id})">删除</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8" class="error-message">${error.message}</td></tr>`;
    }
}

function showInstanceModal() {
    document.getElementById('modal-title').textContent = '添加实例';
    document.getElementById('modal-body').innerHTML = `
        <form id="instance-form">
            <div class="form-group">
                <label>名称 *</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>主机 *</label>
                <input type="text" name="host" required>
            </div>
            <div class="form-group">
                <label>端口 *</label>
                <input type="number" name="port" value="3306" required>
            </div>
            <div class="form-group">
                <label>数据库类型 *</label>
                <select name="db_type" required>
                    <option value="mysql">MySQL</option>
                    <option value="postgresql">PostgreSQL</option>
                </select>
            </div>
            <div class="form-group">
                <label>描述</label>
                <textarea name="description"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
            <button type="button" class="btn btn-outline" onclick="closeModal()">取消</button>
        </form>
    `;
    
    document.getElementById('instance-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        try {
            await apiCall('/admin/instances?' + new URLSearchParams(data), { method: 'POST' });
            showSuccess('实例添加成功');
            closeModal();
            loadInstances();
        } catch (error) {
            showError(error.message);
        }
    });
    
    openModal();
}

async function deleteInstance(id) {
    if (!confirm('确定删除此实例吗？')) return;
    try {
        await apiCall(`/admin/instances/${id}`, { method: 'DELETE' });
        showSuccess('删除成功');
        loadInstances();
    } catch (error) {
        showError(error.message);
    }
}

// 数据库管理
async function loadDatabases() {
    const tbody = document.getElementById('databases-table-body');
    try {
        const data = await apiCall('/admin/databases');
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td>${item.instance_id}</td>
                <td>${item.name}</td>
                <td>${formatDate(item.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteDatabase(${item.id})">删除</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="5" class="error-message">${error.message}</td></tr>`;
    }
}

function showDatabaseModal() {
    document.getElementById('modal-title').textContent = '添加数据库';
    document.getElementById('modal-body').innerHTML = `
        <form id="database-form">
            <div class="form-group">
                <label>实例ID *</label>
                <input type="number" name="instance_id" required>
            </div>
            <div class="form-group">
                <label>数据库名 *</label>
                <input type="text" name="name" required>
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
            <button type="button" class="btn btn-outline" onclick="closeModal()">取消</button>
        </form>
    `;
    
    document.getElementById('database-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        try {
            await apiCall('/admin/databases?' + new URLSearchParams(data), { method: 'POST' });
            showSuccess('数据库添加成功');
            closeModal();
            loadDatabases();
        } catch (error) {
            showError(error.message);
        }
    });
    
    openModal();
}

// 账号管理
async function loadAccounts() {
    const tbody = document.getElementById('accounts-table-body');
    try {
        const data = await apiCall('/admin/accounts');
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td>${item.instance_id}</td>
                <td>${item.username}</td>
                <td>${item.password_enc}</td>
                <td>${item.plugin || '-'}</td>
                <td>${formatDate(item.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteAccount(${item.id})">删除</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7" class="error-message">${error.message}</td></tr>`;
    }
}

function showAccountModal() {
    document.getElementById('modal-title').textContent = '添加账号';
    document.getElementById('modal-body').innerHTML = `
        <form id="account-form">
            <div class="form-group">
                <label>实例ID *</label>
                <input type="number" name="instance_id" required>
            </div>
            <div class="form-group">
                <label>用户名 *</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>密码 *</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>认证插件</label>
                <input type="text" name="plugin" placeholder="mysql_native_password">
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
            <button type="button" class="btn btn-outline" onclick="closeModal()">取消</button>
        </form>
    `;
    
    document.getElementById('account-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        try {
            await apiCall('/admin/accounts?' + new URLSearchParams(data), { method: 'POST' });
            showSuccess('账号添加成功');
            closeModal();
            loadAccounts();
        } catch (error) {
            showError(error.message);
        }
    });
    
    openModal();
}

// 访问密钥管理
async function loadKeys() {
    const tbody = document.getElementById('keys-table-body');
    try {
        const data = await apiCall('/admin/keys');
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td><code>${item.ak}</code></td>
                <td>${item.description || '-'}</td>
                <td>${item.enabled ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-danger">禁用</span>'}</td>
                <td>${item.created_by || '-'}</td>
                <td>${formatDate(item.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteKey(${item.id})">删除</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7" class="error-message">${error.message}</td></tr>`;
    }
}

function showKeyModal() {
    document.getElementById('modal-title').textContent = '添加访问密钥';
    document.getElementById('modal-body').innerHTML = `
        <form id="key-form">
            <div class="form-group">
                <label>密钥 (Access Key) *</label>
                <input type="text" name="ak" required placeholder="例如: api_key_001">
            </div>
            <div class="form-group">
                <label>描述</label>
                <textarea name="description"></textarea>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" name="enabled" checked> 启用
                </label>
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
            <button type="button" class="btn btn-outline" onclick="closeModal()">取消</button>
        </form>
    `;
    
    document.getElementById('key-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const ak = formData.get('ak');
        const description = formData.get('description');
        const enabled = formData.get('enabled') === 'on';
        
        try {
            await apiCall('/admin/keys', {
                method: 'POST',
                body: JSON.stringify({ ak, description, enabled })
            });
            showSuccess('密钥添加成功');
            closeModal();
            loadKeys();
        } catch (error) {
            showError(error.message);
        }
    });
    
    openModal();
}

// 权限管理
async function loadPermissions() {
    const tbody = document.getElementById('permissions-table-body');
    try {
        const data = await apiCall('/admin/permissions');
        tbody.innerHTML = data.items ? data.items.map(item => `
            <tr>
                <td>${item.id}</td>
                <td>${item.key_id}</td>
                <td>${item.instance_id}</td>
                <td>${item.database_id}</td>
                <td>${item.account_id}</td>
                <td>${item.select_only ? '是' : '否'}</td>
                <td>${formatDate(item.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deletePermission(${item.id})">删除</button>
                </td>
            </tr>
        `).join('') : '<tr><td colspan="8">暂无数据</td></tr>';
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8" class="error-message">${error.message}</td></tr>`;
    }
}

function showPermissionModal() {
    document.getElementById('modal-title').textContent = '添加权限';
    document.getElementById('modal-body').innerHTML = `
        <form id="permission-form">
            <div class="form-group">
                <label>密钥ID *</label>
                <input type="number" name="key_id" required>
            </div>
            <div class="form-group">
                <label>实例ID *</label>
                <input type="number" name="instance_id" required>
            </div>
            <div class="form-group">
                <label>数据库ID *</label>
                <input type="number" name="database_id" required>
            </div>
            <div class="form-group">
                <label>账号ID *</label>
                <input type="number" name="account_id" required>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" name="select_only" checked> 只读权限
                </label>
            </div>
            <button type="submit" class="btn btn-primary">添加</button>
            <button type="button" class="btn btn-outline" onclick="closeModal()">取消</button>
        </form>
    `;
    
    document.getElementById('permission-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = {
            key_id: parseInt(formData.get('key_id')),
            instance_id: parseInt(formData.get('instance_id')),
            database_id: parseInt(formData.get('database_id')),
            account_id: parseInt(formData.get('account_id')),
            select_only: formData.get('select_only') === 'on'
        };
        
        try {
            await apiCall('/admin/permissions?' + new URLSearchParams(data), { method: 'POST' });
            showSuccess('权限添加成功');
            closeModal();
            loadPermissions();
        } catch (error) {
            showError(error.message);
        }
    });
    
    openModal();
}

// 审计日志
async function loadAuditLogs() {
    const tbody = document.getElementById('audit-table-body');
    const accessKey = document.getElementById('audit-filter-key').value;
    const operation = document.getElementById('audit-filter-operation').value;
    
    const params = new URLSearchParams({ limit: 100 });
    if (accessKey) params.append('access_key', accessKey);
    if (operation) params.append('operation', operation);
    
    try {
        const data = await apiCall('/admin/audit/logs?' + params);
        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td>${formatDate(item.timestamp)}</td>
                <td><code>${item.access_key || '-'}</code></td>
                <td>${item.client_ip || '-'}</td>
                <td>${item.operation}</td>
                <td title="${item.sql_text || ''}">${(item.sql_text || '-').substring(0, 50)}...</td>
                <td>${item.rows_affected || '-'}</td>
                <td>${item.duration_ms || '-'}</td>
                <td>${item.status === 'success' ? '<span class="badge badge-success">成功</span>' : '<span class="badge badge-danger">失败</span>'}</td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="8" class="error-message">${error.message}</td></tr>`;
    }
}

// 模态框
function openModal() {
    document.getElementById('modal-overlay').classList.add('active');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

// 工具函数
function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('zh-CN');
}

// 初始化
if (authToken) {
    // 尝试验证token
    apiCall('/admin/me').then(data => {
        currentUser = data.user;
        showApp();
    }).catch(() => {
        logout();
    });
} else {
    showLogin();
}
