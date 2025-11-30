import { Router } from 'itty-router';
import { 
  createPasswordHash, 
  verifyPassword, 
  generateToken, 
  verifyToken,
  encryptPassword,
  decryptPassword
} from '../utils/security';

// Define the environment interface for type safety
export interface Env {
  DB: any;
  JWT_SECRET?: string;
  CUSTOM_DOMAIN?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET?: string;
  TURNSTILE_ENFORCE?: string;
}

// Create a new router for authentication routes
const router = Router();

// Register
router.post('/api/auth/register', async (request: Request, env: Env) => {
  try {
    const { email, password } = await request.json() as { email: string; password: string };
    
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'email and password required' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // Basic server-side validation
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!emailRegex.test(email)) {
      return new Response(JSON.stringify({ error: 'Invalid registration data' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
    
    // Password policy: >=8 chars, include 3 of (lower, upper, number, symbol)
    const categories = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].reduce((acc, r) => acc + (r.test(password) ? 1 : 0), 0);
    if (password.length < 8 || categories < 3) {
      return new Response(JSON.stringify({ error: 'Invalid registration data' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // Check if user exists
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) {
      return new Response(JSON.stringify({ error: 'Registration failed' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // Hash password (PBKDF2)
    const passwordHash = await createPasswordHash(password);

    // Create user
    const stmt = env.DB.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    await stmt.bind(email, passwordHash).run();
    const result = await env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(email).first();

    const token = await generateToken(result.id, env);

    const payload = { user: result, token };
    return new Response(JSON.stringify(payload), { 
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

// Login
router.post('/api/auth/login', async (request: Request, env: Env) => {
  try {
    const { email, password } = await request.json() as { email: string; password: string };
    
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'email and password required' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
        status: 401, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
    
    const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE email = ?').bind(normalizedEmail).first();
    if (!user) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
        status: 401, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const isValid = await verifyPassword(password, user.password_hash);
    if (!isValid) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
        status: 401, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const token = await generateToken(user.id, env);
    return new Response(JSON.stringify({ user: { id: user.id, email: normalizedEmail }, token }), { 
      status: 200, 
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