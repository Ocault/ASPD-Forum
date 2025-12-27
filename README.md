# ASPD Forum

Dark, clinical forum interface with JWT authentication.

## Structure

```
/                   Frontend (static HTML/CSS/JS)
/backend            Node.js Express API
```

## Setup

### Prerequisites
- Node.js 18+
- PostgreSQL 14+

### Database

```bash
createdb aspd_forum
psql aspd_forum < backend/sql/001_users.sql
psql aspd_forum < backend/sql/002_forum_tables.sql
psql aspd_forum < backend/sql/003_seed_data.sql
```

### Backend

```bash
cd backend
cp .env.example .env
# Edit .env with your database credentials and JWT secret
npm install
npm start
```

### Frontend

Serve static files from root directory:
```bash
# Using Python
python -m http.server 5500

# Using Node
npx serve -p 5500

# Using VS Code Live Server extension
# Right-click index.html → Open with Live Server
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | API server port | 3000 |
| CORS_ORIGIN | Allowed frontend origin | * |
| JWT_SECRET | Token signing secret | (required) |
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | aspd_forum |
| DB_USER | Database user | postgres |
| DB_PASSWORD | Database password | (empty) |

## Deployment

### Railway

1. Create new project
2. Add PostgreSQL service
3. Add Node.js service from `/backend`
4. Set environment variables from database connection
5. Deploy frontend to separate static host

### Render

**Backend:**
1. New Web Service → Connect repo
2. Root Directory: `backend`
3. Build: `npm install`
4. Start: `npm start`
5. Add PostgreSQL database
6. Set environment variables

**Frontend:**
1. New Static Site → Connect repo
2. Publish Directory: `.` (root)

### Vercel

Frontend only (static):
```bash
vercel --prod
```

Backend requires separate hosting (Railway, Render, Fly.io).

### Heroku

```bash
cd backend
heroku create aspd-forum-api
heroku addons:create heroku-postgresql:mini
heroku config:set JWT_SECRET=your-secret-key
heroku config:set CORS_ORIGIN=https://your-frontend.com
git subtree push --prefix backend heroku main
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /health | No | Health check |
| POST | /register | No | Create account |
| POST | /login | No | Get JWT token |
| GET | /api/rooms | JWT | List rooms |
| GET | /api/room/:id | JWT | Room threads |
| GET | /api/thread/:id | JWT | Thread entries |

## License

MIT
