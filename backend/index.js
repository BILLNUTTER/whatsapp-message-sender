const express = require("express");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
} = require("@whiskeysockets/baileys");
const P = require("pino");

const app = express();
const cors = require("cors");
const userDBPath = path.join(__dirname, "data", "users.json");
const logDBPath = path.join(__dirname, "data", "logs.json");
const authDir = path.join(__dirname, "auth_info_multi");

app.use(express.json());
app.use(
  cors({
    origin: true, // Allow all origins for local dev
    credentials: true,
  })
);
app.use(
  session({
    secret: "whatsapp-broadcast-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
  })
);

// Helper Functions
function loadUsers() {
  return fs.existsSync(userDBPath)
    ? JSON.parse(fs.readFileSync(userDBPath))
    : {};
}

function saveUsers(users) {
  fs.writeFileSync(userDBPath, JSON.stringify(users, null, 2));
}

function saveLog(email, message, numbers, status) {
  const logs = fs.existsSync(logDBPath)
    ? JSON.parse(fs.readFileSync(logDBPath))
    : {};
  if (!logs[email]) logs[email] = [];
  logs[email].push({
    message,
    numbers,
    status,
    timestamp: new Date().toISOString(),
  });
  fs.writeFileSync(logDBPath, JSON.stringify(logs, null, 2));
}

// Local Storage Simulation Middleware
app.use((req, res, next) => {
  if (!req.session.localStore) req.session.localStore = {};
  next();
});

// Register
app.post("/register", async (req, res) => {
  const { email, phone, password } = req.body;
  const users = loadUsers();
  if (users[email])
    return res.status(409).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const now = new Date();
  const expiration = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  users[email] = {
    email,
    phone,
    password: hashed,
    isActive: true,
    sessionStart: now.toISOString(),
    sessionExpires: expiration.toISOString(),
  };

  saveUsers(users);
  console.log(`User registered: ${email}`);
  res.json({ success: true });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users[email];

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid email or password" });

  const now = new Date();
  const expiration = new Date(user.sessionExpires);

  if (!user.isActive || now > expiration) {
    user.isActive = false;
    saveUsers(users);
    return res
      .status(403)
      .json({ error: "Subscription expired. Please renew." });
  }

  req.session.user = { email };
  req.session.localStore.loggedIn = true;
  console.log(`User logged in: ${email}`);
  res.json({ success: true });
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    res.json({ success: true });
  });
});

// Auth Middleware
function requireAuth(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: "Not authenticated" });

  const users = loadUsers();
  const user = users[req.session.user.email];
  const now = new Date();

  if (!user || !user.isActive || new Date(user.sessionExpires) < now) {
    return res.status(403).json({ error: "Session expired or deactivated" });
  }

  next();
}

// WhatsApp Setup
let sockInstance = null;
let currentQRCode = null;
let whatsappStarted = false;

async function startWhatsApp() {
  if (whatsappStarted) return;
  whatsappStarted = true;

  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const { version } = await fetchLatestBaileysVersion();

  sockInstance = makeWASocket({
    logger: P({ level: "silent" }),
    printQRInTerminal: false,
    auth: state,
    version,
  });

  sockInstance.ev.on("connection.update", (update) => {
    const { connection, qr, lastDisconnect } = update;

    if (qr) {
      currentQRCode = qr;
      console.log("QR code updated");
    }

    if (connection === "close") {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      if (statusCode !== DisconnectReason.loggedOut) startWhatsApp();
      else {
        currentQRCode = null;
        whatsappStarted = false;
      }
    }

    if (connection === "open") currentQRCode = null;
  });

  sockInstance.ev.on("creds.update", saveCreds);
}

app.post("/api/start-whatsapp", requireAuth, async (req, res) => {
  try {
    if (whatsappStarted) {
      return res.json({ message: "Already started" });
    }
    await startWhatsApp();
    res.json({ message: "Started WhatsApp connection" });
  } catch (err) {
    res.status(500).json({ error: "Failed to connect" });
  }
});

app.get("/api/whatsapp-qr", requireAuth, (req, res) => {
  if (!currentQRCode) {
    return res.status(404).json({ error: "WhatsApp already connected" });
  }
  res.json({ qr: currentQRCode });
});

async function broadcastMessage(sock, message, jids) {
  for (const jid of jids) {
    await sock.sendMessage(jid, { text: message });
  }
}

app.post("/send-broadcast", requireAuth, async (req, res) => {
  if (!sockInstance)
    return res.status(503).json({ error: "WhatsApp not connected" });

  const { message, numbers } = req.body;
  if (!message || !Array.isArray(numbers) || numbers.length === 0) {
    return res.status(400).json({ error: "Message and numbers required" });
  }

  const jids = numbers.map((num) =>
    num.includes("@s.whatsapp.net") ? num : `${num}@s.whatsapp.net`
  );

  try {
    await broadcastMessage(sockInstance, message, jids);
    saveLog(req.session.user.email, message, numbers, "success");
    res.json({ success: true, sentTo: jids.length });
  } catch (err) {
    console.error("Broadcast failed:", err);
    saveLog(req.session.user.email, message, numbers, "failed");
    res.status(500).json({ error: "Failed to send broadcast" });
  }
});

app.get("/api/logs", requireAuth, (req, res) => {
  const logs = fs.existsSync(logDBPath)
    ? JSON.parse(fs.readFileSync(logDBPath))
    : {};
  res.json(logs[req.session.user.email] || []);
});

app.get("/status", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, email: req.session.user.email });
  } else {
    res.json({ loggedIn: false });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
