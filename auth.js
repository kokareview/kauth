const KAUTH_URL = 'https://kauth.kokareview.workers.dev';
async function register(username, password) {
  const res = await fetch(`${KAUTH_URL}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return await res.json();
}
async function login(username, password) {
  const res = await fetch(`${KAUTH_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (data.ok) {
    localStorage.setItem('kauth_token', data.token); // Автовход
    localStorage.setItem('kauth_user', JSON.stringify(data.user));
  }
  return data;
}
async function update(changes) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/update`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify(changes)
  });
  return await res.json();
}
async function deleteAccount() {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/delete`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${token}` }
  }); 
  if (res.ok) {
    localStorage.removeItem('kauth_token');
    localStorage.removeItem('kauth_user');
  }
  return await res.json();
}
async function createService(id, name) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
    const res = await fetch(`${KAUTH_URL}/api/service/create`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify({ id, name })
  });
  return await res.json();
}
async function saveServiceData(serviceId, data) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/data`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify({ serviceId, data })
  });
  return await res.json();
}
async function getServiceData(serviceId) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/data?service=${serviceId}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await res.json();
}
async function unlinkService(serviceId) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/unlink`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify({ serviceId })
  });
  return await res.json();
}
async function deleteService(serviceId) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/delete`, {
    method: 'DELETE',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify({ serviceId })
  });
  return await res.json();
}
async function listServices() {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/list`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await res.json();
}
async function verifyPassword(password) {
  const token = localStorage.getItem('kauth_token');
  if (!token) return { error: 'Нет токена' };
  const res = await fetch(`${KAUTH_URL}/api/service/verify`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` 
    },
    body: JSON.stringify({ password })
  });
  return await res.json();
}
function isLoggedIn() {
  return !!localStorage.getItem('kauth_token');
}

function getCurrentUser() {
  const user = localStorage.getItem('kauth_user');
  return user ? JSON.parse(user) : null;
}
window.KAuth = {
  register, login, update, deleteAccount,
  createService, saveServiceData, getServiceData,
  unlinkService, deleteService, listServices, verifyPassword,
  isLoggedIn, getCurrentUser
};
