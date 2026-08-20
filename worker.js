

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
    try {
      await env.DB.prepare('INSERT INTO users (email, password, name, is_paid) VALUES (?, ?, ?, 1)').bind(email.toLowerCase(), hash, name).run();
    } catch (e) { return json({ error: 'That email is already registered.' }, 409); }
    const user = await env.DB.prepare('SELECT id, name, is_paid FROM users WHERE email = ?').bind(email.toLowerCase()).first();
    const token = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
    return json({ token, name: user.name, is_paid: user.is_paid });
  }

  if (path === '/api/login' && method === 'POST') {
    const { email, password } = await request.json();
    const user = await env.DB.prepare('SELECT id, password, name, is_paid FROM users WHERE email = ?').bind((email || '').toLowerCase()).first();
    if (!user || user.password !== await hashPassword(password || ''))
      return json({ error: 'Invalid email or password.' }, 401);
    const token = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
    return json({ token, name: user.name, is_paid: user.is_paid });
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
        const user = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(userId).first();
        ctx.waitUntil(syncSheet(env.GOOGLE_WEBHOOK_URL, user.email, progress));
      }
      return json({ success: true });
    }
  }

  // --- COMMUNITY (SKOOL-STYLE) ---
  if (path === '/api/posts' && method === 'GET') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    
    // Get top-level posts with user names and like counts
    const posts = await env.DB.prepare(`
      SELECT p.*, u.name as user_name, 
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = ?) as user_liked
      FROM posts p JOIN users u ON p.user_id = u.id 
      WHERE p.parent_id IS NULL 
      ORDER BY p.created_at DESC
    `).bind(userId).all();

    // Get replies for each post
    for (let post of posts.results) {
      post.replies = await env.DB.prepare(`
        SELECT p.*, u.name as user_name,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = ?) as user_liked
        FROM posts p JOIN users u ON p.user_id = u.id 
        WHERE p.parent_id = ? 
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

  if (path === '/api/likes' && method === 'POST') {
    const userId = await auth(request, env);
    if (!userId) return json({ error: 'Please log in.' }, 401);
    const { post_id } = await request.json();
    try {
      await env.DB.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(post_id, userId).run();
      return json({ liked: true });
    } catch (e) {
      // If already liked, remove it (toggle)
      await env.DB.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').bind(post_id, userId).run();
      return json({ liked: false });
    }
  }

  return json({ error: 'Not found.' }, 404);
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

async function syncSheet(webhookUrl, email, progress) {
  try { await fetch(webhookUrl, { method: 'POST', body: JSON.stringify({ email, progress }) }); } catch (e) {}
}
