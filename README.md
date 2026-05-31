# Lunex — Real-Time Chat

Production-ready chat server: **Node.js + Express + Socket.io + SQLite**, with a polished frontend.

## Quick start (local)

```bash
npm install
npm start
```

Then open **http://localhost:3000/realtime.html** in two different browsers (or normal + incognito) and chat between them.

## Features

- ✅ Real-time messaging (Socket.io, sub-50ms)
- ✅ JWT authentication with bcrypt password hashing
- ✅ SQLite persistence (zero-config, file-based)
- ✅ Channels with history
- ✅ Direct messages (1-on-1)
- ✅ Typing indicators
- ✅ Online presence
- ✅ Rate limiting (per-IP and per-socket)
- ✅ Helmet security headers
- ✅ XSS protection in messages
- ✅ Role-based access (superadmin / admin / member / banned)
- ✅ First user to register becomes superadmin

## Deploy to Render (easiest, free tier)

1. Push this folder to GitHub
2. Go to [render.com](https://render.com) → **New** → **Web Service**
3. Connect the repo
4. Settings:
   - **Build command**: `npm install`
   - **Start command**: `npm start`
   - **Environment variable**: `JWT_SECRET` = some long random string
5. Click Deploy. You get a free URL like `lunex.onrender.com`

## Deploy to Railway

1. Push to GitHub
2. [railway.app](https://railway.app) → **New** → **Deploy from GitHub**
3. Add env var `JWT_SECRET`
4. Done

## Deploy to Fly.io

```bash
fly launch
fly secrets set JWT_SECRET=your-long-random-string
fly deploy
```

## API

- `POST /api/register` — `{ username, email, password }` → `{ token, user }`
- `POST /api/login` — `{ ident, password }` → `{ token, user }`
- `GET /api/me` — current user
- `GET /api/users` — list all
- `GET /api/channels` — list channels
- `POST /api/channels` — create (admin only)
- `GET /api/messages/:channelId?limit=100` — channel history
- `GET /api/dms/:partner?limit=200` — DM history with a user
- `POST /api/admin/role` — `{ username, role }` (admin only)

## Socket.io events

**Client → Server:**
- `channel:join` — `channelId`
- `channel:leave` — `channelId`
- `message:send` — `{ channelId, text, action? }`
- `typing` — `{ channelId }`
- `dm:send` — `{ to, text, encrypted? }`
- `dm:typing` — `{ to }`

**Server → Client:**
- `message:new` — new channel message
- `dm:new` — new DM
- `typing` — `{ username, channelId }`
- `dm:typing` — `{ from }`
- `presence:online` — array of online usernames
- `channel:created` — new channel
- `user:role-changed` — `{ username, role }`

## Security

- bcrypt password hashing (10 rounds)
- JWT tokens expire in 30 days
- Rate limiters: 10 auth req/min, 30 writes/10s, 8 messages/5s
- Helmet security headers
- CORS enabled
- XSS pattern blocklist in messages
- SQL queries use parameter binding (no injection)

## License

Built for the Lunex project.
