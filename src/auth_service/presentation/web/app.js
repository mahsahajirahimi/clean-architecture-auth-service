const $ = (id) => document.getElementById(id);
const state = { token: null, me: null, admin: false, busy: false, timer: null, users: [], groups: [], scopes: [], permissions: [] };
const P = '/access-control';
const notice = (text, error = false) => { $('notice').textContent = text; $('notice').className = error ? 'error' : ''; };
function logout(message = '') {
  clearTimeout(state.timer);
  Object.assign(state, { token: null, me: null, admin: false, users: [], groups: [], scopes: [], permissions: [] });
  $('workspace').hidden = true; $('admin-panel').hidden = true; $('login-panel').hidden = false; $('logout').hidden = true;
  $('session-label').textContent = 'ورود به سامانه'; $('check-result').textContent = '';
  for (const id of ['users', 'groups', 'memberships', 'group-members', 'scopes', 'permissions', 'grants', 'my-permissions']) $(id).replaceChildren();
  document.querySelectorAll('form').forEach((form) => form.reset());
  document.querySelectorAll('#membership-user,#membership-group,#permission-scope,#subject-id,#target-id,#check-user,#check-permission-select').forEach((select) => select.replaceChildren());
  notice(message);
}
async function api(path, options = {}) {
  const tokenAtStart = state.token;
  const headers = { ...options.headers };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try { response = await fetch(path, { ...options, headers, cache: 'no-store', body: options.body === undefined ? undefined : JSON.stringify(options.body) }); }
  catch { throw new Error('ارتباط با سرویس برقرار نشد.'); }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (path !== '/auth/login' && tokenAtStart !== state.token) throw new Error('نشست تغییر کرده است؛ دوباره وارد شوید.');
  if (!response.ok) {
    const error = new Error(response.status === 401 ? 'نام کاربری یا رمز عبور نادرست است.' : response.status === 403 ? 'اجازهٔ انجام این کار را ندارید.' : response.status === 404 ? 'مورد موردنظر پیدا نشد.' : response.status === 409 ? (String(data.detail).includes('administrator cannot') ? 'ادمین اولیه را نمی‌توان غیرفعال کرد.' : 'این مورد تکراری است یا با داده‌های موجود تعارض دارد.') : response.status === 422 || response.status === 400 ? 'ورودی‌ها را بررسی کنید.' : 'خطای سرویس؛ دوباره تلاش کنید.');
    error.status = response.status;
    if (response.status === 401 && path !== '/auth/login') { logout('نشست شما پایان یافته است؛ دوباره وارد شوید.'); error.message = 'نشست شما پایان یافته است؛ دوباره وارد شوید.'; }
    throw error;
  }
  return data;
}
async function run(action) {
  if (state.busy) return;
  state.busy = true;
  $('check-result').textContent = ''; 
  const controls = [...document.querySelectorAll('input,select,button')].map((element) => [element, element.disabled]);
  controls.forEach(([element]) => { element.disabled = true; });
  try { await action(); } catch (error) { notice(error.message || 'عملیات انجام نشد.', true); }
  finally { controls.forEach(([element, disabled]) => { element.disabled = disabled; }); state.busy = false; }
}
function form(id, action) {
  $(id).addEventListener('submit', (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.currentTarget));
    run(() => action(data));
  });
}
async function all(path) {
  const result = [];
  for (let offset = 0; ; offset += 100) {
    const page = await api(`${path}${path.includes('?') ? '&' : '?'}limit=100&offset=${offset}`);
    result.push(...page);
    if (page.length < 100) return result;
  }
}
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function empty(container, message = 'موردی وجود ندارد.') { container.replaceChildren(element('li', message, 'empty')); }
function options(id, rows, label, placeholder = 'انتخاب کنید') {
  const select = $(id), previous = select.value;
  select.replaceChildren(new Option(placeholder, ''));
  rows.forEach((row) => select.add(new Option(label(row), row.id)));
  if (rows.some((row) => row.id === previous)) select.value = previous;
}
function actionButton(text, action, danger = false) {
  const button = element('button', text, `small-button${danger ? ' danger' : ''}`);
  button.type = 'button'; button.addEventListener('click', () => run(action)); return button;
}
const scopeName = (id) => state.scopes.find((scope) => scope.id === id)?.name || id;
const permissionName = (p) => `${scopeName(p.scope_id)} : ${p.name}`;
function renderSubjects() {
  const rows = $('subject-type').value === 'user' ? state.users : state.groups;
  options('subject-id', rows, (row) => row.username || row.name);
}
function renderTargets() {
  const isScope = $('target-type').value === 'scope';
  options('target-id', isScope ? state.scopes : state.permissions, isScope ? (s) => s.name : permissionName);
  $('scope-warning').hidden = !isScope;
}
function renderAdmin() {
  const users = $('users'); users.replaceChildren();
  state.users.forEach((user) => {
    const row = element('tr'), action = element('td');
    const button = actionButton(user.is_active ? 'غیرفعال‌کردن' : 'فعال‌کردن', async () => {
      await api(`/users/${user.id}/status`, { method: 'PATCH', body: { is_active: !user.is_active } });
      await refreshAdmin(); notice('وضعیت کاربر تغییر کرد.');
    }, user.is_active);
    if (user.id === state.me.id) { button.disabled = true; button.textContent = 'ادمین'; }
    action.append(button); row.append(element('td', user.username), element('td', user.is_active ? 'فعال' : 'غیرفعال'), action); users.append(row);
  });
  const groups = $('groups'); groups.replaceChildren();
  state.groups.length ? state.groups.forEach((group) => groups.append(element('li', group.name))) : empty(groups);
  options('membership-user', state.users, (u) => u.username);
  options('membership-group', state.groups, (g) => g.name);
  options('permission-scope', state.scopes, (s) => s.name);
  options('check-user', state.users, (u) => u.username, 'خودم');
  options('check-permission-select', state.permissions, permissionName);
  const scopes = $('scopes'); scopes.replaceChildren();
  state.scopes.forEach((scope) => scopes.append(element('li', scope.name)));
  const permissions = $('permissions'); permissions.replaceChildren();
  state.permissions.forEach((permission) => { const row = element('tr'), id = element('td'); id.append(element('code', permission.id)); row.append(element('td', scopeName(permission.scope_id)), element('td', permission.name), id); permissions.append(row); });
  renderSubjects(); renderTargets();
}
async function refreshAdmin() {
  const [users, groups, scopes] = await Promise.all([all('/users'), all('/groups'), all(`${P}/scopes`)]);
  const pages = await Promise.all(scopes.map((scope) => all(`${P}/scopes/${scope.id}/permissions`)));
  Object.assign(state, { users, groups, scopes, permissions: pages.flat() });
  renderAdmin(); await Promise.all([loadMemberships(), loadGroupMembers(), loadGrants()]);
}
async function loadMemberships() {
  const userId = $('membership-user').value, list = $('memberships');
  if (!userId) return empty(list, 'کاربری انتخاب نشده است.');
  const groups = await all(`/users/${userId}/groups`); list.replaceChildren();
  if (!groups.length) return empty(list);
  groups.forEach((group) => { const li = element('li'); li.append(element('span', group.name), actionButton('حذف عضویت', async () => { await api(`/groups/${group.id}/members/${userId}`, { method: 'DELETE' }); await Promise.all([loadMemberships(), loadGroupMembers(), loadMine()]); notice('عضویت حذف شد.'); }, true)); list.append(li); });
}
async function loadGroupMembers() {
  const groupId = $('membership-group').value, list = $('group-members');
  if (!groupId) return empty(list, 'گروهی انتخاب نشده است.');
  const users = await all(`/groups/${groupId}/members`); list.replaceChildren();
  users.length ? users.forEach((user) => list.append(element('li', user.username))) : empty(list);
}
async function loadGrants() {
  const subject = $('subject-id').value, type = $('subject-type').value, list = $('grants');
  if (!subject) return empty(list, 'گیرنده‌ای انتخاب نشده است.');
  const grants = await all(`${P}/grants?subject_type=${encodeURIComponent(type)}&subject_id=${encodeURIComponent(subject)}`); list.replaceChildren();
  if (!grants.length) return empty(list);
  grants.forEach((grant) => {
    const target = grant.target_type === 'scope' ? `Scope: ${scopeName(grant.target_id)}` : (() => { const p = state.permissions.find((item) => item.id === grant.target_id); return p ? permissionName(p) : grant.target_id; })();
    const li = element('li'); li.append(element('span', target), actionButton('حذف مجوز', async () => { await api(`${P}/grants/${grant.subject_type}/${grant.subject_id}/${grant.target_type}/${grant.target_id}`, { method: 'DELETE' }); await Promise.all([loadGrants(), loadMine()]); notice('مجوز مستقیم حذف شد؛ ممکن است دسترسی از مسیر دیگری باقی بماند.'); }, true)); list.append(li);
  });
}
async function loadMine() {
  const result = await api(`${P}/me/permissions`), list = $('my-permissions'); list.replaceChildren();
  if (!result.permission_ids.length) return empty(list, 'در حال حاضر مجوزی ندارید.');
  result.permission_ids.forEach((id) => { const li = element('li'), p = state.permissions.find((item) => item.id === id); li.append(element('span', p ? permissionName(p) : 'Permission'), element('code', id)); list.append(li); });
}
form('login-form', async (data) => {
  const result = await api('/auth/login', { method: 'POST', body: data });
  state.token = result.access_token; $('login-form').reset();
  try {
    state.me = await api('/auth/me');
    try { await api('/users?limit=1'); state.admin = true; } catch (error) { if (error.status !== 403) throw error; state.admin = false; }
    $('login-panel').hidden = true; $('workspace').hidden = false; $('logout').hidden = false; $('admin-panel').hidden = !state.admin;
    $('session-label').textContent = `${state.me.username} · ${state.admin ? 'ادمین' : 'کاربر'}`;
    $('check-user-label').hidden = !state.admin; $('check-select-label').hidden = !state.admin; $('check-input-label').hidden = state.admin;
    $('check-permission-select').required = state.admin; $('check-permission-id').required = !state.admin;
    if (state.admin) await refreshAdmin();
    await loadMine(); notice('وارد شدید.');
    clearTimeout(state.timer); state.timer = setTimeout(() => logout('نشست شما پایان یافته است؛ دوباره وارد شوید.'), result.expires_in * 1000);
  } catch (error) { logout(); throw error; }
});
form('user-form', async (data) => { await api('/users', { method: 'POST', body: data }); $('user-form').reset(); await refreshAdmin(); notice('کاربر ساخته شد.'); });
form('group-form', async (data) => { await api('/groups', { method: 'POST', body: data }); $('group-form').reset(); await refreshAdmin(); notice('گروه ساخته شد.'); });
form('membership-form', async (data) => { await api(`/groups/${data.group_id}/members`, { method: 'POST', body: { user_id: data.user_id } }); await Promise.all([loadMemberships(), loadGroupMembers(), loadMine()]); notice('عضویت اضافه شد.'); });
form('scope-form', async (data) => { const scope = await api(`${P}/scopes`, { method: 'POST', body: data }); $('scope-form').reset(); await refreshAdmin(); $('permission-scope').value = scope.id; notice('Scope ساخته شد.'); });
form('permission-form', async (data) => { await api(`${P}/scopes/${data.scope_id}/permissions`, { method: 'POST', body: { name: data.name } }); $('permission-form').elements.name.value = ''; await refreshAdmin(); notice('Permission ساخته شد.'); });
form('grant-form', async (data) => { await api(`${P}/grants`, { method: 'POST', body: data }); await Promise.all([loadGrants(), loadMine()]); notice('مجوز تخصیص داده شد.'); });
form('check-form', async (data) => {
  const permission = state.admin ? $('check-permission-select').value : data.permission_id.trim();
  const user = state.admin ? data.user_id : '';
  const result = await api(user ? `${P}/users/${user}/check` : `${P}/me/check`, { method: 'POST', body: { permission_id: permission } });
  $('check-result').textContent = result.allowed ? 'دسترسی مجاز است.' : 'دسترسی مجاز نیست.';
  $('check-result').className = result.allowed ? 'allowed' : 'denied';
});
$('subject-type').addEventListener('change', () => run(async () => { renderSubjects(); await loadGrants(); }));
$('subject-id').addEventListener('change', () => run(loadGrants));
$('target-type').addEventListener('change', () => { renderTargets(); });
$('membership-user').addEventListener('change', () => run(loadMemberships));
$('membership-group').addEventListener('change', () => run(loadGroupMembers));
$('check-form').addEventListener('input', () => { $('check-result').textContent = ''; });
$('refresh').addEventListener('click', () => run(async () => { if (state.admin) await refreshAdmin(); await loadMine(); notice('اطلاعات به‌روز شد.'); }));
$('logout').addEventListener('click', () => logout('خارج شدید.'));
