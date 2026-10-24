export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
    const url = new URL(request.url);
    const path = url.pathname;
    try {
       if (path === '/login' && request.method === 'GET') {
         return await handleSSOLogin(request, env, url, corsHeaders);
       }
       if (path === '/sso/login' && request.method === 'POST') {
          return await handleSSOSubmit(request, env, url, corsHeaders);
       }
      if (path === '/api/register' && request.method === 'POST') return await handleRegister(request, env, corsHeaders);
      if (path === '/api/login' && request.method === 'POST') return await handleLogin(request, env, corsHeaders);
      if (path === '/api/update' && request.method === 'POST') return await handleUpdate(request, env, corsHeaders);
      if (path === '/api/delete' && request.method === 'DELETE') return await handleDelete(request, env, corsHeaders);
      if (path === '/api/service/create' && request.method === 'POST') return await handleCreateService(request, env, corsHeaders);
      if (path === '/api/service/list' && request.method === 'GET') return await handleListServices(request, env, corsHeaders);
      if (path === '/api/service/delete' && request.method === 'DELETE') return await handleDeleteService(request, env, corsHeaders);
      if (path === '/api/service/unlink' && request.method === 'POST') return await handleUnlinkService(request, env, corsHeaders);
      if (path === '/api/service/verify' && request.method === 'POST') return await handleVerifyService(request, env, corsHeaders);
      if (path === '/api/service/data' && request.method === 'POST') return await handleSaveData(request, env, corsHeaders);
      if (path === '/api/service/data' && request.method === 'GET') return await handleGetData(request, env, url, corsHeaders);
      return json({ error: 'Не найдено' }, 404, corsHeaders);
    } catch (e) {
      return json({ error: e.message }, 500, corsHeaders);
    }
  }
};
function json(obj, code = 200, cors = {}) {
  return new Response(JSON.stringify(obj), {
    status: code,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}
async function hashPassword(password) {
  const msg = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest('SHA-256', msg);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function generateToken() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function getUser(env, request) {
  const auth = request.headers.get('Authorization');
  if (!auth) return null;
  const token = auth.replace('Bearer ', '');
  const sessionStr = await env.KV.get(`session:${token}`);
  if (!sessionStr) return null;
  const session = JSON.parse(sessionStr);
  if (session.expires_at < Date.now()) {
    await env.KV.delete(`session:${token}`);
    return null;
  }
  const userStr = await env.KV.get(`user:${session.username}`);
  if (!userStr) return null;
  const user = JSON.parse(userStr);
  return { ...user, token };
}
async function handleRegister(request, env, cors) {
  const { username, password } = await request.json();
  if (!username || password.length < 4) return json({ error: 'Введи логин и пароль (мин. 4 символа)' }, 400, cors);  
  const existing = await env.KV.get(`user:${username}`);
  if (existing) return json({ error: 'Этот ник занят' }, 409, cors);
  const hash = await hashPassword(password);
  const userData = { username, password_hash: hash, avatar: 'https://letmeowcdn.github.io/1/2.png', created_at: Date.now() }; 
  await env.KV.put(`user:${username}`, JSON.stringify(userData));
  return json({ ok: true }, 200, cors);
}
async function handleLogin(request, env, cors) {
  const { username, password } = await request.json();
  const userStr = await env.KV.get(`user:${username}`);
  if (!userStr) return json({ error: 'Неверный логин или пароль' }, 401, cors);
  const user = JSON.parse(userStr);
  const hash = await hashPassword(password);
  if (user.password_hash !== hash) return json({ error: 'Неверный логин или пароль' }, 401, cors);
  const token = generateToken();
  const sessionData = { username: user.username, expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000 };
  await env.KV.put(`session:${token}`, JSON.stringify(sessionData), { expirationTtl: 30 * 24 * 60 * 60 });
  return json({ ok: true, token, user: { username: user.username, avatar: user.avatar } }, 200, cors);
}
async function handleUpdate(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const body = await request.json();
  const userKey = `user:${user.username}`;
  const userData = JSON.parse(await env.KV.get(userKey));
  if (body.newPassword) userData.password_hash = await hashPassword(body.newPassword);
  if (body.newUsername) {
    await env.KV.delete(userKey);
    userData.username = body.newUsername;
    await env.KV.put(`user:${body.newUsername}`, JSON.stringify(userData));
    return json({ ok: true, message: 'Ник изменён. Перезайди в аккаунт.' }, 200, cors);
  }
  if (body.newAvatar) userData.avatar = body.newAvatar;
  await env.KV.put(userKey, JSON.stringify(userData));
  return json({ ok: true }, 200, cors);
}
async function handleDelete(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  await env.KV.delete(`user:${user.username}`);
  await env.KV.delete(`session:${user.token}`);
  const list = await env.KV.list({ prefix: `data:` });
  for (const key of list.keys) {
    if (key.name.endsWith(`:${user.username}`)) {
      await env.KV.delete(key.name);
    }
  }
  return json({ ok: true }, 200, cors);
}
async function handleCreateService(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const { id, name } = await request.json();
  const secret = generateToken();
  const serviceData = { id, name, owner: user.username, secret };
  await env.KV.put(`service:${id}`, JSON.stringify(serviceData));
  return json({ ok: true, secret }, 200, cors);
}
async function handleListServices(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const list = await env.KV.list({ prefix: 'service:' });
  const myServices = []; 
  for (const key of list.keys) {
    const s = JSON.parse(await env.KV.get(key.name));
    if (s.owner === user.username) myServices.push(s);
  }
  return json({ ok: true, services: myServices }, 200, cors);
}
async function handleDeleteService(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const { serviceId } = await request.json();
  const serviceStr = await env.KV.get(`service:${serviceId}`);
  if (!serviceStr) return json({ error: 'Сервис не найден' }, 404, cors);
  const service = JSON.parse(serviceStr);
  if (service.owner !== user.username) return json({ error: 'Нет прав' }, 403, cors);
  await env.KV.delete(`service:${serviceId}`);
  return json({ ok: true, message: 'Сервис удалён' }, 200, cors);
}
async function handleUnlinkService(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const { serviceId } = await request.json();
  await env.KV.delete(`data:${serviceId}:${user.username}`);
  return json({ ok: true, message: 'Отвязано' }, 200, cors);
}
async function handleVerifyService(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const { password } = await request.json();
  const userStr = await env.KV.get(`user:${user.username}`);
  const userData = JSON.parse(userStr);
  if (userData.password_hash !== await hashPassword(password)) {
    return json({ error: 'Неверный пароль' }, 401, cors);
  }
  return json({ ok: true, message: 'Подтверждено' }, 200, cors);
}
async function handleSaveData(request, env, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const { serviceId, data } = await request.json();
  await env.KV.put(`data:${serviceId}:${user.username}`, JSON.stringify(data));
  return json({ ok: true }, 200, cors);
}
async function handleGetData(request, env, url, cors) {
  const user = await getUser(env, request);
  if (!user) return json({ error: 'Не авторизован' }, 401, cors);
  const serviceId = url.searchParams.get('service');
  const dataStr = await env.KV.get(`data:${serviceId}:${user.username}`);  
  return json({ ok: true, data: dataStr ? JSON.parse(dataStr) : {} }, 200, cors);
}
async function handleSSOLogin(request, env, url, cors) {
  const redirectUrl = url.searchParams.get('redirect') || '/';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Вход в KAuth</title>
    </head>
    <body>
      <h2>Вход через KAuth</h2>
      <form action="/sso/login?redirect=${encodeURIComponent(redirectUrl)}" method="POST">
        <input type="text" name="username" placeholder="Логин" required>
        <input type="password" name="password" placeholder="Пароль" required>
        <button type="submit">Войти</button>
      </form>
    </body>
    </html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
async function handleSSOSubmit(request, env, url, cors) {
  const redirectUrl = url.searchParams.get('redirect') || '/';
  const formData = await request.formData();
  const username = formData.get('username');
  const password = formData.get('password');
  const userStr = await env.KV.get(`user:${username}`);
  if (!userStr) {
    return new Response('Неверный логин или пароль. <a href="javascript:history.back()">Назад</a>', { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const user = JSON.parse(userStr);
  const hash = await hashPassword(password);  
  if (user.password_hash !== hash) {
    return new Response('Неверный логин или пароль. <a href="javascript:history.back()">Назад</a>', { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const token = generateToken();
  const sessionData = { username: user.username, expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000 };
  await env.KV.put(`session:${token}`, JSON.stringify(sessionData), { expirationTtl: 30 * 24 * 60 * 60 });
  const finalRedirect = new URL(redirectUrl);
  finalRedirect.searchParams.set('kauth_token', token);
  return Response.redirect(finalRedirect.toString(), 302);
    }
