import { Router } from 'itty-router';
import { verifyToken, encryptPassword, decryptPassword } from '../utils/security';

// Define the environment interface for type safety
export interface Env {
  DB: any;
  JWT_SECRET?: string;
}

interface PasswordEntry {
  id: number;
  user_id: number;
  website: string;
  username: string;
  password: string;
  created_at: string;
  tags: string;
}

// Create a new router for password routes
const router = Router();

// Middleware to authenticate user
const authenticate = async (request: Request, env: Env) => {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const token = authHeader.substring(7);
  const userId = await verifyToken(token, env);
  
  if (!userId) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Add userId to request for use in routes
  (request as any).userId = userId;
};

// Get all passwords for user
router.get('/api/passwords', async (request: Request & { userId?: number }, env: Env) => {
  const authResponse = await authenticate(request, env);
  if (authResponse) return authResponse;

  try {
    const stmt = env.DB.prepare('SELECT id, website, username, tags, password, created_at FROM passwords WHERE user_id = ? ORDER BY created_at DESC');
    const results = await stmt.bind(request.userId).all();

    // Decrypt passwords
    const decrypted = results.results.map((p: PasswordEntry) => ({
      ...p,
      password: decryptPassword(p.password, `user_${request.userId}`)
    }));

    return new Response(JSON.stringify(decrypted), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// Create password
router.post('/api/passwords', async (request: Request & { userId?: number }, env: Env) => {
  const authResponse = await authenticate(request, env);
  if (authResponse) return authResponse;

  try {
    const { website, username = '', tags = [], password } = await request.json() as {
      website: string;
      username?: string;
      tags?: string[];
      password: string;
    };

    if (!website || !password) {
      return new Response(JSON.stringify({ error: 'website and password required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Sanitize inputs
    const sanitizedWebsite = website.trim().slice(0, 500);
    const sanitizedUsername = (username || '').trim().slice(0, 200);

    // Encrypt password
    const encryptedPassword = await encryptPassword(password, `user_${request.userId}`);

    const tagsStr = Array.isArray(tags) ? tags.join(',') : '';
    const stmt = env.DB.prepare('INSERT INTO passwords (user_id, website, username, tags, password) VALUES (?, ?, ?, ?, ?)');
    const insertResult = await stmt.bind(request.userId, sanitizedWebsite, sanitizedUsername, tagsStr, encryptedPassword).run();
    const result = await env.DB.prepare('SELECT id, website, username, tags, created_at FROM passwords WHERE id = ?').bind(insertResult.meta.last_row_id).first();

    return new Response(JSON.stringify({ ...result, password }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// Update password
router.put('/api/passwords/:id', async (request: Request & { userId?: number }, env: Env) => {
  const authResponse = await authenticate(request, env);
  if (authResponse) return authResponse;

  try {
    const { id } = request.params || {};
    const { website, username = '', tags = [], password } = await request.json() as {
      website: string;
      username?: string;
      tags?: string[];
      password: string;
    };

    if (!id || !website || !password) {
      return new Response(JSON.stringify({ error: 'id, website and password required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Sanitize inputs
    const sanitizedWebsite = website.trim().slice(0, 500);
    const sanitizedUsername = (username || '').trim().slice(0, 200);

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, request.userId).first();
    if (!exists) {
      return new Response(JSON.stringify({ error: 'Password not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Encrypt password
    const encryptedPassword = await encryptPassword(password, `user_${request.userId}`);

    const tagsStr = Array.isArray(tags) ? tags.join(',') : '';
    const stmt = env.DB.prepare('UPDATE passwords SET website = ?, username = ?, tags = ?, password = ? WHERE id = ? AND user_id = ?');
    await stmt.bind(sanitizedWebsite, sanitizedUsername, tagsStr, encryptedPassword, id, request.userId).run();

    return new Response(JSON.stringify({ success: true, id, website: sanitizedWebsite, username: sanitizedUsername, tags }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// Delete password
router.delete('/api/passwords/:id', async (request: Request & { userId?: number }, env: Env) => {
  const authResponse = await authenticate(request, env);
  if (authResponse) return authResponse;

  try {
    const { id } = request.params || {};

    if (!id) {
      return new Response(JSON.stringify({ error: 'id required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, request.userId).first();
    if (!exists) {
      return new Response(JSON.stringify({ error: 'Password not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const stmt = env.DB.prepare('DELETE FROM passwords WHERE id = ? AND user_id = ?');
    await stmt.bind(id, request.userId).run();

    return new Response(JSON.stringify({ success: true, id }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

export default router;