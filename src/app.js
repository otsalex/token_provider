import { createServerClient, parseCookieHeader, serializeCookieHeader } from '@supabase/ssr'
import { Router } from 'express';
import { createClient } from '@supabase/supabase-js';
import express from 'express';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const router = Router();

const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

export const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

const supabase = (context) => {
  return createServerClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          const cookies = context.req.headers.cookie;
          return parseCookieHeader(cookies)
        },
        setAll(cookiesToSet) {
          if (!context.res.headersSent) {
            cookiesToSet.forEach(({ name, value, options }) =>
              context.res.appendHeader('Set-Cookie', serializeCookieHeader(name, value, options))
            )
          }
        },
    },
    }
  )
}

// PATHS
router.get('/login', async (req, res) => {
  try {
    const { data, error } = await supabase({req, res}).auth.signInWithOAuth({
      provider: 'twitter',
      options: {
        redirectTo: process.env.TWITTER_REDIRECT_URL,
        scopes: 'tweet.read users.read offline.access'
      }
    });

    if (error || !data.url) {
      console.error('Twitter OAuth Error:', error);
      return res.status(500).json({ error: 'OAuth initialization failed' });
    }

    return res.redirect(data.url);
  } catch (err) {
    console.error('Twitter OAuth Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/callback', async (req, res) => {
  const code = req.query.code;

  if (code) {
    const { data: session, error } = await supabase({req, res}).auth.exchangeCodeForSession(code);

    if (error) {
      console.error('Error exchanging code:', error);
      return res.status(500).json({ error: 'Failed to exchange code' });
    }

    const { user, access_token, refresh_token, expires_at, provider_token } = session.session;

    const { error: dbError } = await supabaseAdmin
      .from('user_tokens')
      .upsert({
        user_id: user.id,
        access_token,
        refresh_token,
        expires_at,
      });

    if (dbError) {
      console.error('Error saving tokens:', dbError);
      return res.status(500).json({ error: 'Failed to save tokens' });
    }
  }
  res.redirect('/');
});

router.get('/get-token', async (req, res) => {
  const userId = req.query.user_id;

  try {
    const { data: userToken, error } = await supabaseAdmin
      .from('user_tokens')
      .select('access_token, refresh_token, expires_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !userToken) {
      console.error('Error retrieving tokens:', error);
      return res.status(404).json({ error: 'Tokens not found for user' });
    }

    const currentTime = Math.floor(Date.now() / 1000);
    if (userToken.expires_at > currentTime) {
      return res.json({
        access_token: userToken.access_token,
        expires_at: userToken.expires_at,
      });
    }

    const refreshResponse = await refreshToken(userId);
    
    if (refreshResponse.error) {
      console.error('Failed to refresh token:', refreshResponse.error);
      return res.status(500).json({ error: 'Failed to refresh token' });
    }

    const refreshedData = refreshResponse;
    return res.json({
      access_token: refreshedData.access_token,
      message: 'Token refreshed and retrieved successfully.',
    });
  } catch (err) {
    console.error('Error retrieving tokens:', err);
    res.status(500).json({ error: 'Failed to retrieve tokens' });
  }
});


async function refreshToken(user_id) {
  try {
    const { data: userToken, error } = await supabaseAdmin
      .from('user_tokens')
      .select('refresh_token, expires_at')
      .eq('user_id', user_id)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !userToken) {
      console.error('Error retrieving tokens:', error);
      throw new Error('Tokens not found for user');
    }
    const response = await fetch('https://api.x.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: userToken.refresh_token,
        client_id: process.env.CLIENT_ID
      }),
    });

    if (!response.ok) {
      console.error('Failed to refresh token:', await response.text());
      throw new Error('Failed to refresh token');
    }

    const refreshedTokens = await response.json();

    const { error: dbError } = await supabaseAdmin
      .from('user_tokens')
      .update({
        access_token: refreshedTokens.access_token,
        refresh_token: refreshedTokens.refresh_token || userToken.refresh_token,
        expires_at: refreshedTokens.expires_at,
      })
      .eq('user_id', user_id);

    if (dbError) {
      console.error('Error updating tokens:', dbError);
      throw new Error('Failed to update tokens');
    }

    return {
      message: 'Token refreshed successfully.',
      access_token: refreshedTokens.access_token,
    };
  } catch (err) {
    console.error('Error refreshing token:', err);
    throw err;
  }
}


// APP SETUP

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (for login page)
app.use(express.static('./src/public'));

// Authentication Routes
app.use('/', router);

// Simple login page route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});