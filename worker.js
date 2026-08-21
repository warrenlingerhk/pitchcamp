

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await handleApi(request, env, ctx, url); }
      catch (e) { return json({ error: e.message }, 500); }
    }
    return env.ASSETS.fetch(request);
  },
};

async function handleApi(request, env, ctx, url) {
  const path = url.pathname;
  const method = request.method;

  // --- AUTH ---
  if (path === '/api/signup' && method === 'POST') {
    const { name, email, password } = await request.json();
    if (!email || !password || String(password).length < 6)
      return json({ error: 'Email and a password of 6+ characters required.' }, 400);
    
    const hash = await hashPassword(password);
    const maxUser = await env.DB.prepare('SELECT MAX(user_number) as max_num FROM users').first();
    const nextUserNumber = (maxUser.max_num || 0) + 1;
    
    try {
      await env.DB.prepare("INSERT INTO users (email, password, name, is_paid, user_number, created_at) VALUES (?, ?, ?, 1, ?, datetime('now'))").bind(email.toLowerCase(), hash, name, nextUserNumber).run();
    } catch (e) { 
      return json({ error: 'That email is already registered.' }, 409); 
    }
    
    const user = await env.DB.prepare('SELECT id, name, is_paid, is_admin, user_number FROM users WHERE email = ?').bind(email.toLowerCase()).first();
    const token = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
    
    return json({ token, name: user.name, is_paid: user.is_paid, is_admin: user.is_admin, user_number: user.user_number });
  }

  if (path === '/api/login' && method === 'POST') {
    const { email, password } = await request.json();
    const user = await env.DB.prepare('SELECT id, password, name, is_paid, is_admin, user_number, banned FROM users WHERE email = ?').bind((email || '').toLowerCase()).first();
    
    if (!user || user.password !== await hashPassword(password || ''))
      return json({ error: 'Invalid email or password.' }, 401);
    
    if (user.banned) 
      return json({ error: 'This account has been banned.' }, 403);
    
    const token = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
    
    return json({ token, name: user.name, is_paid: user.is_paid, is_admin: user.is_admin, user_number: user.user_number });
  }

  // --- PROGRESS ---
  if (path === '/api/progress') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in again.' }, 401);
    
    if (method === 'GET') {
      const res = await env.DB.prepare('SELECT item_id, completed, note FROM progress WHERE user_id = ?').bind(userId).all();
      return json(res.results);
    }
    
    if (method === 'POST') {
      const { progress } = await request.json();
      for (const item of progress) {
        await env.DB.prepare("INSERT OR REPLACE INTO progress (user_id, item_id, completed, note, updated_at) VALUES (?, ?, ?, ?, datetime('now'))").bind(userId, item.item_id, item.completed ? 1 : 0, item.note || '').run();
      }
      if (env.GOOGLE_WEBHOOK_URL) {
        const user = await env.DB.prepare('SELECT email, name, user_number FROM users WHERE id = ?').bind(userId).first();
        ctx.waitUntil(syncSheet(env.GOOGLE_WEBHOOK_URL, user.email, user.name, user.user_number, progress));
      }
      return json({ success: true });
    }
  }

  // --- COMMUNITY ---
  if (path === '/api/posts' && method === 'GET') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    
    const posts = await env.DB.prepare(`
      SELECT p.*, u.name as user_name, u.id as user_id,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = ?) as user_liked
      FROM posts p JOIN users u ON p.user_id = u.id 
      WHERE p.parent_id IS NULL AND u.banned = 0
      ORDER BY p.pinned DESC, p.created_at DESC
    `).bind(userId).all();

    for (let post of posts.results) {
      post.replies = await env.DB.prepare(`
        SELECT p.*, u.name as user_name, u.id as user_id,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = ?) as user_liked
        FROM posts p JOIN users u ON p.user_id = u.id 
        WHERE p.parent_id = ? AND u.banned = 0
        ORDER BY p.created_at ASC
      `).bind(userId, post.id).all();
    }
    return json(posts.results);
  }

  if (path === '/api/posts' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const { content, parent_id } = await request.json();
    if (!content) return json({ error: 'Post cannot be empty.' }, 400);
    const res = await env.DB.prepare('INSERT INTO posts (user_id, content, parent_id) VALUES (?, ?, ?)').bind(userId, content, parent_id || null).run();
    return json({ id: res.meta.last_row_id });
  }

  if (path === '/api/posts/delete' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.is_admin) return json({ error: 'Admin only.' }, 403);
    const { post_id } = await request.json();
    await env.DB.prepare('DELETE FROM posts WHERE id = ? OR parent_id = ?').bind(post_id, post_id).run();
    return json({ success: true });
  }

  if (path === '/api/posts/pin' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.is_admin) return json({ error: 'Admin only.' }, 403);
    const { post_id } = await request.json();
    await env.DB.prepare('UPDATE posts SET pinned = NOT pinned WHERE id = ?').bind(post_id).run();
    return json({ success: true });
  }

  if (path === '/api/posts/pin-course' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.is_admin) return json({ error: 'Admin only.' }, 403);
    const { post_id } = await request.json();
    await env.DB.prepare('UPDATE posts SET pinned_to_course = NOT pinned_to_course WHERE id = ?').bind(post_id).run();
    return json({ success: true });
  }

  if (path === '/api/posts/comments' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.is_admin) return json({ error: 'Admin only.' }, 403);
    const { post_id } = await request.json();
    await env.DB.prepare('UPDATE posts SET comments_disabled = NOT comments_disabled WHERE id = ?').bind(post_id).run();
    return json({ success: true });
  }

  if (path === '/api/users/ban' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.is_admin) return json({ error: 'Admin only.' }, 403);
    const { user_id } = await request.json();
    await env.DB.prepare('UPDATE users SET banned = 1 WHERE id = ?').bind(user_id).run();
    return json({ success: true });
  }

  if (path === '/api/reports' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const { post_id, reason } = await request.json();
    await env.DB.prepare('INSERT INTO reports (post_id, reporter_id, reason) VALUES (?, ?, ?)').bind(post_id, userId, reason || '').run();
    return json({ success: true });
  }

  if (path === '/api/likes' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const { post_id } = await request.json();
    try {
      await env.DB.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(post_id, userId).run();
      return json({ liked: true });
    } catch (e) {
      await env.DB.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').bind(post_id, userId).run();
      return json({ liked: false });
    }
  }

  // --- ADMIN DASHBOARD ---
  if (path === '/api/admin/stats' && method === 'GET') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const users = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    const posts = await env.DB.prepare('SELECT COUNT(*) as c FROM posts WHERE parent_id IS NULL').first();
    const reports = await env.DB.prepare('SELECT COUNT(*) as c FROM reports').first();
    const mod1 = await env.DB.prepare("SELECT COUNT(DISTINCT user_id) as c FROM progress WHERE item_id = 'welcome' AND completed = 1").first();
    return json({ users: users.c, posts: posts.c, reports: reports.c, mod1: mod1.c });
  }

  if (path === '/api/admin/reports' && method === 'GET') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const res = await env.DB.prepare(`
      SELECT r.id, r.reason, r.created_at, r.resolved,
      p.content as post_content, p.id as post_id, p.user_id,
      u.name as reporter_name, au.name as reported_user_name, au.is_admin as reported_user_is_admin
      FROM reports r
      JOIN posts p ON r.post_id = p.id
      JOIN users u ON r.reporter_id = u.id
      JOIN users au ON p.user_id = au.id
      ORDER BY r.resolved ASC, r.created_at DESC LIMIT 50
    `).all();
    return json(res.results);
  }

  if (path === '/api/admin/reports/resolve' && method === 'POST') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const { report_id, resolved } = await request.json();
    await env.DB.prepare('UPDATE reports SET resolved = ? WHERE id = ?').bind(resolved ? 1 : 0, report_id).run();
    return json({ success: true });
  }

  if (path === '/api/admin/reports/delete' && method === 'POST') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const { report_id } = await request.json();
    await env.DB.prepare('DELETE FROM reports WHERE id = ?').bind(report_id).run();
    return json({ success: true });
  }

  if (path === '/api/admin/users' && method === 'GET') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const res = await env.DB.prepare('SELECT id, name, email, user_number, is_paid, banned, created_at FROM users ORDER BY user_number ASC').all();
    return json(res.results);
  }

  if (path === '/api/admin/analytics' && method === 'GET') {
    if (!await requireAdmin(request, env)) return json({ error: 'Forbidden' }, 403);
    const totalUsers = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    const activeLearners = await env.DB.prepare('SELECT COUNT(DISTINCT user_id) as c FROM progress').first();
    const elite = await env.DB.prepare("SELECT COUNT(DISTINCT user_id) as c FROM progress WHERE item_id = 'reflection6' AND completed = 1").first();
    const eliteRate = totalUsers.c > 0 ? Math.round((elite.c / totalUsers.c) * 100) : 0;
    const totalPosts = await env.DB.prepare('SELECT COUNT(*) as c FROM posts WHERE parent_id IS NULL').first();
    const engagement = totalUsers.c > 0 ? (totalPosts.c / totalUsers.c).toFixed(1) : 0;
    const totalReports = await env.DB.prepare('SELECT COUNT(*) as c FROM reports').first();
    const healthRatio = totalPosts.c > 0 ? (totalReports.c / totalPosts.c).toFixed(2) : 0;
    return json({ totalUsers: totalUsers.c, activeLearners: activeLearners.c, eliteRate: eliteRate, engagement: engagement, healthRatio: healthRatio });
  }

  return json({ error: 'Not found.' }, 404);
}

async function requireAdmin(request, env) {
  const userId = await auth(request, env);
  if (!userId) return null;
  const user = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(userId).first();
  if (!user || !user.is_admin) return null;
  return userId;
}

async function auth(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  const s = await env.DB.prepare('SELECT user_id FROM sessions WHERE token = ?').bind(token).first();
  return s ? s.user_id : null;
}

async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function syncSheet(webhookUrl, email, name, user_number, progress) {
  try { await fetch(webhookUrl, { method: 'POST', body: JSON.stringify({ email, name, user_number, progress }) }); } catch (e) {}
}
