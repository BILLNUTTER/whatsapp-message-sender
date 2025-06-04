const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason
} = require('@adiwajshing/baileys');
const P = require('pino');

const app = express();

const cors = require('cors');
const userDBPath = path.join(__dirname, 'data', 'users.json');
const logDBPath = path.join(__dirname, 'data', 'logs.json');
const authDir = path.join(__dirname, 'auth_info_multi');

app.use(express.json());


// CORS middleware
app.use(cors({
  origin: 'https://billbroadcastsender.netlify.app/',
  credentials: true,               // Allow cookies/session credentials from frontend
}));

app.use(session({
  secret: 'whatsapp-broadcast-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
}));

// Load and save users
function loadUsers() {
  return fs.existsSync(userDBPath) ? JSON.parse(fs.readFileSync(userDBPath)) : {};
}
function saveUsers(users) {
  fs.writeFileSync(userDBPath, JSON.stringify(users, null, 2));
}

// Save logs
function saveLog(email, message, numbers, status) {
  const logs = fs.existsSync(logDBPath) ? JSON.parse(fs.readFileSync(logDBPath)) : {};
  if (!logs[email]) logs[email] = [];
  logs[email].push({
    message,
    numbers,
    status,
    timestamp: new Date().toISOString(),
  });
  fs.writeFileSync(logDBPath, JSON.stringify(logs, null, 2));
}

// Register
app.post('/register', async (req, res) => {
  const { email, phone, password } = req.body;
  const users = loadUsers();
  if (users[email]) return res.status(409).json({ error: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  users[email] = { email, phone, password: hashed };
  saveUsers(users);
  res.json({ success: true });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users[email];
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  req.session.user = { email };
  res.json({ success: true });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Failed to logout' });
    res.json({ success: true });
  });
});

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// WhatsApp Setup
let sockInstance = null;
let currentQRCode = null;

async function startWhatsApp() {
  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const { version } = await fetchLatestBaileysVersion();

  sockInstance = makeWASocket({
    logger: P({ level: 'silent' }),
    printQRInTerminal: false,
    auth: state,
    version,
  });

  sockInstance.ev.on('connection.update', (update) => {
    const { connection, qr, lastDisconnect } = update;

    if (qr) {
      currentQRCode = qr;
      console.log('New QR code received. Use /api/whatsapp-qr to fetch it.');
    }

    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      console.log('Connection closed. Code:', statusCode);

      if (statusCode !== DisconnectReason.loggedOut) {
        console.log('Reconnecting...');
        startWhatsApp();
      } else {
        console.log('Logged out');
        currentQRCode = null;
      }
    } else if (connection === 'open') {
      console.log('WhatsApp connected');
      currentQRCode = null;
    }
  });

  sockInstance.ev.on('creds.update', saveCreds);
}

startWhatsApp();

// QR code endpoint
app.get('/api/whatsapp-qr', (req, res) => {
  if (!currentQRCode) {
    return res.status(404).json({ error: 'No QR available. WhatsApp is connected.' });
  }
  res.json({ qr: currentQRCode });
});

// Broadcast message
async function broadcastMessage(sock, message, jids) {
  for (const jid of jids) {
    await sock.sendMessage(jid, { text: message });
  }
}

app.post('/send-broadcast', requireAuth, async (req, res) => {
  if (!sockInstance) {
    return res.status(503).json({ error: 'WhatsApp not connected' });
  }

  const { message, numbers } = req.body;
  if (!message || !Array.isArray(numbers) || numbers.length === 0) {
    return res.status(400).json({ error: 'Message and numbers are required' });
  }

  const jids = numbers.map(num => num.includes('@s.whatsapp.net') ? num : `${num}@s.whatsapp.net`);

  try {
    await broadcastMessage(sockInstance, message, jids);
    saveLog(req.session.user.email, message, numbers, 'success');
    res.json({ success: true, sentTo: jids.length });
  } catch (err) {
    console.error('Broadcast failed:', err);
    saveLog(req.session.user.email, message, numbers, 'failed');
    res.status(500).json({ error: 'Failed to send broadcast' });
  }
});

// Fetch logs
app.get('/api/logs', requireAuth, (req, res) => {
  const logs = fs.existsSync(logDBPath) ? JSON.parse(fs.readFileSync(logDBPath)) : {};
  res.json(logs[req.session.user.email] || []);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
