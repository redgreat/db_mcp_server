// 用户管理功能模块
// 此文件扩展 admin.js，添加用户管理和基于角色的权限控制

// ==================== 访问密钥用户分配功能 ====================

// 显示密钥用户分配对话框
async function showAssignUsersModal(keyId) {
    try {
        // 获取所有用户和已分配用户
        const [allUsersRes, assignedUsersRes] = await Promise.all([
            apiCall('/admin/users?page_size=1000'),  // 获取所有用户
            apiCall(`/admin/keys/${keyId}/users`)     // 获取已分配用户
        ]);

        const assignedUserIds = new Set(assignedUsersRes.users.map(u => u.id));

        document.getElementById('modal-title').textContent = '分配用户权限';
        document.getElementById('modal-body').innerHTML = `
            <form id="assign-users-form">
                <div class="form-group">
                    <label>选择可以访问此密钥的用户</label>
                    <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px;">
                        ${allUsersRes.items.map(user => `
                            <label style="display: block; padding: 8px; cursor: pointer; border-bottom: 1px solid #f0f0f0;">
                                <input type="checkbox" name="user_ids" value="${user.id}" 
                                       ${assignedUserIds.has(user.id) ? 'checked' : ''}
                                       style="margin-right: 8px;">
                                <strong>${user.username}</strong>
                                <span class="badge ${user.role === 'admin' ? 'badge-danger' : 'badge-info'}" style="margin-left: 8px;">
                                    ${user.role === 'admin' ? '管理员' : '普通用户'}
                                </span>
                                ${user.email ? `<span style="color: #666; margin-left: 8px;">(${user.email})</span>` : ''}
                            </label>
                        `).join('')}
                    </div>
                    <small style="color: #666; display: block; margin-top: 8px;">
                        选中的用户可以在密钥列表中看到此密钥
                    </small>
                </div>
                <button type="submit" class="btn btn-primary">确认分配</button>
            </form>
        `;

        document.getElementById('assign-users-form').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const userIds = formData.getAll('user_ids').map(id => parseInt(id));

            try {
                await apiCall(`/admin/keys/${keyId}/users`, {
                    method: 'POST',
                    body: JSON.stringify(userIds)
                });
                closeModal();
                alert('用户分配成功');
                if (window.loadKeys) loadKeys(window.currentKeysPage || 1);
            } catch (error) {
                alert('分配失败: ' + error.message);
            }
        };

        openModal();
    } catch (error) {
        alert('加载用户列表失败: ' + error.message);
    }
}

// 移除密钥的用户分配
async function removeKeyUser(keyId, userId, username) {
    if (confirm(`确认取消用户 "${username}" 对此密钥的访问权限？`)) {
        try {
            await apiCall(`/admin/keys/${keyId}/users/${userId}`, { method: 'DELETE' });
            if (window.loadKeys) loadKeys(window.currentKeysPage || 1);
        } catch (error) {
            alert('取消分配失败: ' + error.message);
        }
    }
}

// ==================== 用户管理功能 ====================

// 全局变量：当前用户角色
window.currentUserRole = null;

// 初始化用户管理页面（动态创建HTML）
function initUserManagement() {
    // 在主内容区添加用户管理页面
    const mainContent = document.querySelector('.main-content');
    if (!mainContent) return;

    const usersSection = document.createElement('div');
    usersSection.id = 'users-content';
    usersSection.className = 'content-section';
    usersSection.innerHTML = `
        <div class="content-header">
            <h3>用户管理</h3>
            <button class="btn btn-primary" onclick="showCreateUserModal()" id="create-user-btn">
                <span class="icon">➕</span> 添加用户
            </button>
        </div>
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>用户名</th>
                        <th>邮箱</th>
                        <th>角色</th>
                        <th>状态</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody id="users-table-body">
                    <tr><td colspan="7" class="loading">加载中...</td></tr>
                </tbody>
            </table>
        </div>
        <div id="users-pagination" class="pagination" style="margin-top: 16px;"></div>
    `;
    mainContent.appendChild(usersSection);

    // 在侧边栏添加用户管理菜单
    const sidebar = document.querySelector('.sidebar-nav');
    if (sidebar) {
        const usersMenuItem = document.createElement('a');
        usersMenuItem.href = '#';
        usersMenuItem.className = 'nav-item';
        usersMenuItem.id = 'users-menu';
        usersMenuItem.dataset.page = 'users';
        usersMenuItem.style.display = 'none';  // 默认隐藏，仅管理员可见
        usersMenuItem.innerHTML = `
            <span class="icon">👥</span>
            用户管理
        `;
        usersMenuItem.addEventListener('click', (e) => {
            e.preventDefault();
            switchPage('users');
        });
        sidebar.appendChild(usersMenuItem);
    }
}

// 用户管理分页变量
let currentUsersPage = 1;
const usersPageSize = 10;

// 加载用户列表
async function loadUsers(page = 1) {
    currentUsersPage = page;
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;

    const params = new URLSearchParams({ page, page_size: usersPageSize });

    try {
        const data = await apiCall('/admin/users?' + params);
        tbody.innerHTML = data.items.map(user => `
            <tr>
                <td>${user.id}</td>
                <td><strong>${user.username}</strong></td>
                <td>${user.email || '-'}</td>
                <td>
                    <span class="badge ${user.role === 'admin' ? 'badge-danger' : 'badge-info'}">
                        ${user.role === 'admin' ? '管理员' : '普通用户'}
                    </span>
                </td>
                <td>
                    <span class="badge ${user.is_active ? 'badge-success' : 'badge-secondary'}">
                        ${user.is_active ? '启用' : '禁用'}
                    </span>
                </td>
                <td>${formatDate(user.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="showEditUserModal(${user.id}, '${user.username}', '${user.email || ''}', '${user.role}', ${user.is_active})" style="margin-right: 4px;">编辑</button>
                    <button class="btn btn-sm btn-warning" onclick="showResetPasswordModal(${user.id}, '${user.username}')" style="margin-right: 4px;">重置密码</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')">删除</button>
                </td>
            </tr>
        `).join('');

        // 渲染分页器
        renderPagination('users-pagination', data.total, data.page, data.page_size, loadUsers);
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7">加载失败: ${error.message}</td></tr>`;
    }
}

// 显示创建用户对话框
function showCreateUserModal() {
    document.getElementById('modal-title').textContent = '创建新用户';
    document.getElementById('modal-body').innerHTML = `
        <form id="create-user-form">
            <div class="form-group">
                <label>用户名</label>
                <input type="text" name="username" required placeholder="用户登录名">
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" name="password" required placeholder="初始密码">
            </div>
            <div class="form-group">
                <label>邮箱（可选）</label>
                <input type="email" name="email" placeholder="user@example.com">
            </div>
            <div class="form-group">
                <label>角色</label>
                <select name="role" required>
                    <option value="user">普通用户（只读权限）</option>
                    <option value="admin">管理员（完全权限）</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">创建用户</button>
        </form>
    `;

    document.getElementById('create-user-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        try {
            await apiCall('/admin/users', {
                method: 'POST',
                body: JSON.stringify({
                    username: fd.get('username'),
                    password: fd.get('password'),
                    email: fd.get('email') || '',
                    role: fd.get('role')
                })
            });
            closeModal();
            loadUsers(currentUsersPage);
        } catch (error) {
            alert('创建失败: ' + error.message);
        }
    };
    openModal();
}

// 显示编辑用户对话框
function showEditUserModal(userId, username, email, role, isActive) {
    document.getElementById('modal-title').textContent = `编辑用户: ${username}`;
    document.getElementById('modal-body').innerHTML = `
        <form id="edit-user-form">
            <div class="form-group">
                <label>角色</label>
                <select name="role" required>
                    <option value="user" ${role === 'user' ? 'selected' : ''}>普通用户（只读权限）</option>
                    <option value="admin" ${role === 'admin' ? 'selected' : ''}>管理员（完全权限）</option>
                </select>
            </div>
            <div class="form-group">
                <label>状态</label>
                <select name="is_active" required>
                    <option value="true" ${isActive ? 'selected' : ''}>启用</option>
                    <option value="false" ${!isActive ? 'selected' : ''}>禁用</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">保存修改</button>
        </form>
    `;

    document.getElementById('edit-user-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        try {
            await apiCall(`/admin/users/${userId}`, {
                method: 'PUT',
                body: JSON.stringify({
                    role: fd.get('role'),
                    is_active: fd.get('is_active') === 'true'
                })
            });
            closeModal();
            loadUsers(currentUsersPage);
        } catch (error) {
            alert('更新失败: ' + error.message);
        }
    };
    openModal();
}

// 显示重置密码对话框
function showResetPasswordModal(userId, username) {
    document.getElementById('modal-title').textContent = `重置密码: ${username}`;
    document.getElementById('modal-body').innerHTML = `
        <form id="reset-password-form">
            <div class="form-group">
                <label>新密码</label>
                <input type="password" name="new_password" required placeholder="输入新密码">
            </div>
            <div class="form-group">
                <label>确认密码</label>
                <input type="password" name="confirm_password" required placeholder="再次输入新密码">
            </div>
            <button type="submit" class="btn btn-primary">重置密码</button>
        </form>
    `;

    document.getElementById('reset-password-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const newPassword = fd.get('new_password');
        const confirmPassword = fd.get('confirm_password');

        if (newPassword !== confirmPassword) {
            alert('两次输入的密码不一致');
            return;
        }

        try {
            await apiCall(`/admin/users/${userId}/reset-password`, {
                method: 'POST',
                body: JSON.stringify({ new_password: newPassword })
            });
            closeModal();
            alert('密码重置成功');
        } catch (error) {
            alert('重置失败: ' + error.message);
        }
    };
    openModal();
}

// 删除用户
async function deleteUser(userId, username) {
    if (confirm(`确认删除用户 "${username}"？\n此操作不可恢复。`)) {
        try {
            await apiCall(`/admin/users/${userId}`, { method: 'DELETE' });
            loadUsers(currentUsersPage);
        } catch (error) {
            alert('删除失败: ' + error.message);
        }
    }
}

// 应用基于角色的界面控制
function applyRoleBasedUI() {
    if (!window.currentUserRole) return;

    if (window.currentUserRole === 'user') {
        // 普通用户：隐藏所有操作按钮
        // 隐藏添加按钮
        const addButtons = document.querySelectorAll('.btn-primary:not(#logout-btn):not(#change-pwd-btn)');
        addButtons.forEach(btn => {
            if (!btn.closest('form')) {  // 不隐藏表单内submit按钮
                btn.style.display = 'none';
            }
        });

        // 隐藏删除、编辑等操作按钮（这些会在加载数据时动态生成，需要在加载后再次隐藏）
        hideActionButtons();

        // 隐藏用户管理菜单
        const usersMenu = document.getElementById('users-menu');
        if (usersMenu) usersMenu.style.display = 'none';

        // 隐藏审计日志菜单（普通用户不应看到）
        const auditMenu = document.getElementById('audit-menu');
        if (auditMenu) auditMenu.style.display = 'none';
    } else if (window.currentUserRole === 'admin') {
        // 管理员：显示用户管理菜单和审计日志菜单
        const usersMenu = document.getElementById('users-menu');
        if (usersMenu) usersMenu.style.display = 'flex';

        const auditMenu = document.getElementById('audit-menu');
        if (auditMenu) auditMenu.style.display = 'flex';
    }
}

// 隐藏操作按钮（普通用户）
function hideActionButtons() {
    if (window.currentUserRole !== 'user') return;

    // 隐藏表格中的操作按钮
    setTimeout(() => {
        document.querySelectorAll('.btn-danger, .btn-warning, .btn-outline').forEach(btn => {
            if (!btn.id || (!btn.id.includes('logout') && !btn.id.includes('pwd'))) {
                btn.style.display = 'none';
            }
        });

        // 隐藏添加权限、添加白名单等按钮
        document.querySelectorAll('.btn-xs').forEach(btn => {
            btn.style.display = 'none';
        });
    }, 100);
}

// 扩展原有的 showApp 函数
const originalShowApp = window.showApp;
window.showApp = function () {
    if (originalShowApp) originalShowApp();

    // 获取并保存用户角色
    if (window.currentUser && window.currentUser.role) {
        window.currentUserRole = window.currentUser.role;
    }

    // 应用基于角色的UI控制
    applyRoleBasedUI();
};

// 扩展原有的 switchPage 函数
const originalSwitchPage = window.switchPage;
window.switchPage = function (page) {
    if (originalSwitchPage) originalSwitchPage(page);

    // 如果切换到用户管理页面，加载用户列表
    if (page === 'users') {
        loadUsers();
    }

    // 在切换页面后重新应用权限控制
    hideActionButtons();
};

// 扩展原有的登录处理
const originalLoginHandler = document.getElementById('login-form')?.onsubmit;
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm && !originalLoginHandler) {
        loginForm.addEventListener('submit', async (e) => {
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

                window.authToken = data.token;
                window.currentUser = data.user;
                window.currentUserRole = data.user.role;  // 保存角色
                localStorage.setItem('authToken', window.authToken);

                // 初始化用户管理功能
                initUserManagement();

                // 显示应用
                if (window.showApp) window.showApp();
            } catch (error) {
                errorEl.textContent = error.message;
            }
        });
    }

    // 页面加载时初始化
    initUserManagement();

    // 如果已登录，应用权限控制
    if (window.authToken && window.currentUser) {
        window.currentUserRole = window.currentUser.role;
        applyRoleBasedUI();
    }
});
