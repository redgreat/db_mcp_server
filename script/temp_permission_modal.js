// 3. 关联权限弹窗（支持多选 + 搜索 + 分页）
async function showAddPermissionModal(keyId) {
    const connsRes = await apiCall('/admin/connections');
    const permsRes = await apiCall('/admin/permissions');

    // 找出该密钥已授权的连接ID
    const existingConnIds = permsRes.items
        .filter(p => p.key_id === keyId)
        .map(p => p.connection_id);

    // 过滤掉已授权的连接
    const availableConns = connsRes.items.filter(c => !existingConnIds.includes(c.id));

    let currentPage = 1;
    const pageSize = 10;
    let searchTerm = '';

    function renderConnectionList() {
        // 搜索过滤
        const filtered = availableConns.filter(c =>
            searchTerm === '' ||
            c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            c.host.toLowerCase().includes(searchTerm.toLowerCase()) ||
            c.database.toLowerCase().includes(searchTerm.toLowerCase())
        );

        // 分页
        const totalPages = Math.ceil(filtered.length / pageSize);
        const startIdx = (currentPage - 1) * pageSize;
        const endIdx = startIdx + pageSize;
        const pageConns = filtered.slice(startIdx, endIdx);

        const listHtml = pageConns.length > 0 ? pageConns.map(c => `
            <div style="margin-bottom: 8px;">
                <label style="display: flex; align-items: center; cursor: pointer; padding: 8px; border-radius: 4px; transition: background 0.2s;" 
                       onmouseover="this.style.background='#f1f5f9'" 
                       onmouseout="this.style.background='transparent'">
                    <input type="checkbox" name="connection_ids" value="${c.id}" style="margin-right: 8px;">
                    <div style="flex: 1;">
                        <div style="font-weight: 500;">${c.name}</div>
                        <div style="font-size: 12px; color: #64748b;">${c.host}:${c.port} / ${c.database}</div>
                    </div>
                </label>
            </div>
        `).join('') : '<div style="text-align: center; padding: 20px; color: #64748b;">没有找到匹配的连接</div>';

        const paginationHtml = totalPages > 1 ? `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e2e8f0;">
                <button type="button" class="btn btn-sm btn-outline" 
                        onclick="window.permModalChangePage(${currentPage - 1})" 
                        ${currentPage === 1 ? 'disabled' : ''}>上一页</button>
                <span style="color: #64748b; font-size: 13px;">第 ${currentPage} / ${totalPages} 页 (共 ${filtered.length} 条)</span>
                <button type="button" class="btn btn-sm btn-outline" 
                        onclick="window.permModalChangePage(${currentPage + 1})" 
                        ${currentPage === totalPages ? 'disabled' : ''}>下一页</button>
            </div>
        ` : filtered.length > 0 ? `<div style="text-align: center; margin-top: 12px; color: #64748b; font-size: 13px;">共 ${filtered.length} 条</div>` : '';

        document.getElementById('connection-list').innerHTML = listHtml;
        document.getElementById('pagination').innerHTML = paginationHtml;
    }

    document.getElementById('modal-title').textContent = '为密钥分配权限（可多选）';
    document.getElementById('modal-body').innerHTML = `
        <form id="perm-form">
            ${availableConns.length > 5 ? `
            <div class="form-group">
                <label>搜索连接</label>
                <input type="text" id="search-conn" placeholder="输入名称、主机或数据库名搜索..." 
                       style="margin-bottom: 12px;">
            </div>
            ` : ''}
            <div class="form-group">
                <label>选择数据库连接（可多选）${existingConnIds.length > 0 ? ' - 已授权 ' + existingConnIds.length + ' 个' : ''}</label>
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px;" id="connection-list">
                    加载中...
                </div>
                <div id="pagination"></div>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="select_only" checked> 只读模式 (仅限查询)</label>
            </div>
            <button type="submit" class="btn btn-primary">确认授权</button>
        </form>
    `;

    // 搜索功能
    const searchInput = document.getElementById('search-conn');
    if (searchInput) {
        searchInput.oninput = (e) => {
            searchTerm = e.target.value;
            currentPage = 1;
            renderConnectionList();
        };
    }

    // 分页功能
    window.permModalChangePage = (page) => {
        currentPage = page;
        renderConnectionList();
    };

    // 初始渲染
    renderConnectionList();

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
