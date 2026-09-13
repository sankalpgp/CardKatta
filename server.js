const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const port = Number(process.env.PORT || 3000);
const contentTypes = {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.ico': 'image/x-icon',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg'
};
const database = new DatabaseSync(path.join(__dirname, 'katta.sqlite'));

database.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        reset_token TEXT,
        reset_expires_at INTEGER
    )
`);

function sendJson(response, status, body) {
    response.writeHead(status, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(body));
}

function normalizeEmail(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return { hash, salt };
}

function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 8;
}

async function readJson(request) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (body.length > 1_000_000) {
            throw new Error('Request body is too large.');
        }
    }
    return JSON.parse(body || '{}');
}

function handleAuth(request, response, pathname, body) {
    if (pathname === '/api/auth/register') {
        const email = normalizeEmail(body.email);
        const password = body.password;
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return sendJson(response, 400, { error: 'Enter a valid email address.' });
        }
        if (!isValidPassword(password)) {
            return sendJson(response, 400, { error: 'Password must be at least 8 characters.' });
        }
        if (database.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
            return sendJson(response, 409, { error: 'An account with this email already exists.' });
        }
        const { hash, salt } = hashPassword(password);
        database.prepare(
            'INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)'
        ).run(email, hash, salt);
        return sendJson(response, 201, { email });
    }

    if (pathname === '/api/auth/login') {
        const email = normalizeEmail(body.email);
        const password = body.password;
        const user = database.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user || !isValidPassword(password)) {
            return sendJson(response, 401, { error: 'Wrong email or password.' });
        }
        const { hash } = hashPassword(password, user.password_salt);
        if (!crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.password_hash, 'hex'))) {
            return sendJson(response, 401, { error: 'Wrong email or password.' });
        }
        return sendJson(response, 200, { email: user.email });
    }

    if (pathname === '/api/auth/forgot-password') {
        const email = normalizeEmail(body.email);
        const user = database.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (!user) {
            return sendJson(response, 404, { error: 'No account was found for that email.' });
        }
        const resetToken = crypto.randomBytes(24).toString('hex');
        database.prepare(
            'UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE id = ?'
        ).run(resetToken, Date.now() + 15 * 60 * 1000, user.id);
        return sendJson(response, 200, {
            message: 'Reset token created. In production, send it by email.',
            resetToken
        });
    }

    if (pathname === '/api/auth/reset-password') {
        const token = typeof body.token === 'string' ? body.token.trim() : '';
        const user = database.prepare(
            'SELECT id FROM users WHERE reset_token = ? AND reset_expires_at > ?'
        ).get(token, Date.now());
        if (!user) {
            return sendJson(response, 400, { error: 'Reset token is invalid or expired.' });
        }
        if (!isValidPassword(body.password)) {
            return sendJson(response, 400, { error: 'Password must be at least 8 characters.' });
        }
        const { hash, salt } = hashPassword(body.password);
        database.prepare(
            'UPDATE users SET password_hash = ?, password_salt = ?, reset_token = NULL, reset_expires_at = NULL WHERE id = ?'
        ).run(hash, salt, user.id);
        return sendJson(response, 200, { message: 'Password updated.' });
    }

    return sendJson(response, 404, { error: 'Endpoint not found.' });
}

const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    if (request.method === 'POST' && url.pathname.startsWith('/api/auth/')) {
        try {
            return handleAuth(request, response, url.pathname, await readJson(request));
        } catch (error) {
            return sendJson(response, 400, { error: error.message });
        }
    }

    const requestedPath = url.pathname === '/' ? '/login_index.html' : url.pathname;
    const filePath = path.join(__dirname, requestedPath);
    if (!filePath.startsWith(__dirname) || !fs.existsSync(filePath)) {
        return sendJson(response, 404, { error: 'Not found.' });
    }
    response.writeHead(200, {
        'Content-Type': contentTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream'
    });
    return fs.createReadStream(filePath).pipe(response);
});

server.listen(port, () => {
    console.log(`Katta is running at http://localhost:${port}`);
});
