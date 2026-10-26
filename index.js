
"use strict";

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const QRCode = require("qrcode");

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
} = require("@whiskeysockets/baileys");

const P = require("pino");

const app = express();
const PORT = process.env.PORT || 3000;

// --------------------------------------------------
// Paths and directories
// --------------------------------------------------

const dataDir = path.join(__dirname, "data");
const userDBPath = path.join(dataDir, "users.json");
const logDBPath = path.join(dataDir, "logs.json");

// Every user's WhatsApp credentials live in a separate directory.
const authRootDir = path.join(__dirname, "auth_info_multi");

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(authRootDir, { recursive: true });

for (const file of [userDBPath, logDBPath]) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "{}", "utf8");
  }
}

// IMPORTANT:
// The old shared auth_info_multi credentials are deliberately preserved.
// New per-user sessions use subdirectories inside auth_info_multi.

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

const allowedOrigins = new Set([
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://127.0.0.1:5501",
  "http://localhost:5501",
  "https://billbroadcastsender.netlify.app",
]);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin is not allowed by CORS."));
    },
    credentials: true,
  })
);

const sessionSecret =
  process.env.SESSION_SECRET ||
  "local-development-secret-change-before-deploying";

if (
  process.env.NODE_ENV === "production" &&
  !process.env.SESSION_SECRET
) {
  throw new Error(
    "Set SESSION_SECRET in your production environment before starting the server."
  );
}

app.use(
  session({
    name: "whatsapp.sid",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
  })
);

// --------------------------------------------------
// Database helpers
// --------------------------------------------------

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (err) {
    console.error(`Could not read ${filePath}:`, err.message);
    throw err;
  }
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function loadUsers() {
  return readJSON(userDBPath);
}

function saveUsers(users) {
  writeJSON(userDBPath, users);
}

function loadLogs() {
  return readJSON(logDBPath);
}

function saveLogs(logs) {
  writeJSON(logDBPath, logs);
}

function saveLog(email, message, numbers, status, details = {}) {
  try {
    const logs = loadLogs();

    if (!Array.isArray(logs[email])) {
      logs[email] = [];
    }

    logs[email].push({
      message,
      numbers,
      status,
      timestamp: new Date().toISOString(),
      ...details,
    });

    if (logs[email].length > 500) {
      logs[email] = logs[email].slice(-500);
    }

    saveLogs(logs);
  } catch (err) {
    console.error("Could not save log:", err.message);
  }
}

// --------------------------------------------------
// Per-user WhatsApp connection manager
// --------------------------------------------------

// Keyed by normalized user email.
// Each entry owns its own socket, QR, auth directory and timers.

const whatsappConnections = new Map();

function getUserAuthDir(email) {
  const normalizedEmail = email.trim().toLowerCase();

  // Avoid using email addresses directly in filesystem paths.
  const userFolder = crypto
    .createHash("sha256")
    .update(normalizedEmail)
    .digest("hex");

  return path.join(authRootDir, userFolder);
}

function getWhatsAppState(email) {
  const normalizedEmail = email.trim().toLowerCase();

  if (!whatsappConnections.has(normalizedEmail)) {
    whatsappConnections.set(normalizedEmail, {
      email: normalizedEmail,
      authDir: getUserAuthDir(normalizedEmail),
      socket: null,
      qr: null,
      started: false,
      connected: false,
      reconnectTimer: null,
      manuallyDisconnected: false,
      startupPromise: null,
      connectionError: null,
    });
  }

  return whatsappConnections.get(normalizedEmail);
}

function clearReconnectTimer(state) {
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
}

// --------------------------------------------------
// Registration
// --------------------------------------------------

app.post("/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters long.",
      });
    }

    const users = loadUsers();

    if (users[normalizedEmail]) {
      return res.status(409).json({
        error: "User already exists.",
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    const now = new Date();
    const expiration = new Date(
      now.getTime() + 30 * 24 * 60 * 60 * 1000
    );

    users[normalizedEmail] = {
      name: typeof name === "string" ? name.trim() : "",
      email: normalizedEmail,
      phone: typeof phone === "string" ? phone.trim() : "",
      password: hashed,
      isActive: true,
      sessionStart: now.toISOString(),
      sessionExpires: expiration.toISOString(),
    };

    saveUsers(users);

    console.log(`User registered: ${normalizedEmail}`);

    return res.status(201).json({
      success: true,
      message: "Registration successful.",
    });
  } catch (err) {
    console.error("Registration error:", err);

    return res.status(500).json({
      error: "Registration failed due to a server error.",
    });
  }
});

// --------------------------------------------------
// Login
// --------------------------------------------------

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = loadUsers();
    const user = users[normalizedEmail];

    if (
      !user ||
      typeof user.password !== "string" ||
      !(await bcrypt.compare(password, user.password))
    ) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    const now = new Date();
    const expiration = new Date(user.sessionExpires);

    if (
      !user.isActive ||
      !user.sessionExpires ||
      Number.isNaN(expiration.getTime()) ||
      now > expiration
    ) {
      user.isActive = false;
      saveUsers(users);

      return res.status(403).json({
        error: "Subscription expired. Please renew.",
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regeneration error:", err);

        return res.status(500).json({
          error: "Could not create login session.",
        });
      }

      req.session.user = {
        email: normalizedEmail,
      };

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr);

          return res.status(500).json({
            error: "Could not save login session.",
          });
        }

        console.log(`User logged in: ${normalizedEmail}`);

        return res.json({
          success: true,
          user: {
            email: normalizedEmail,
            name: user.name || "",
          },
        });
      });
    });
  } catch (err) {
    console.error("Login error:", err);

    return res.status(500).json({
      error: "Login failed due to a server error.",
    });
  }
});

// --------------------------------------------------
// Logout
// --------------------------------------------------

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);

      return res.status(500).json({
        error: "Logout failed.",
      });
    }

    res.clearCookie("whatsapp.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });

    return res.json({ success: true });
  });
});

// --------------------------------------------------
// Authentication middleware
// --------------------------------------------------

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      error: "Not authenticated. Please log in again.",
    });
  }

  try {
    const users = loadUsers();
    const email = req.session.user.email;
    const user = users[email];

    if (!user || !user.isActive) {
      return res.status(403).json({
        error: "Account not found or deactivated.",
      });
    }

    const expiration = new Date(user.sessionExpires);

    if (
      !user.sessionExpires ||
      Number.isNaN(expiration.getTime()) ||
      expiration < new Date()
    ) {
      return res.status(403).json({
        error: "Subscription expired or account deactivated.",
      });
    }

    return next();
  } catch (err) {
    console.error("Authentication error:", err);

    return res.status(500).json({
      error: "Could not verify authentication.",
    });
  }
}

// --------------------------------------------------
// Reconnect one user's WhatsApp connection
// --------------------------------------------------

function scheduleWhatsAppReconnect(state) {
  if (
    state.manuallyDisconnected ||
    state.reconnectTimer ||
    state.started
  ) {
    return;
  }

  state.reconnectTimer = setTimeout(async () => {
    state.reconnectTimer = null;

    if (state.manuallyDisconnected || state.started) {
      return;
    }

    try {
      await startWhatsApp(state);
    } catch (err) {
      console.error(
        `WhatsApp reconnect error for ${state.email}:`,
        err.message
      );
    }
  }, 5000);
}

// --------------------------------------------------
// Start one user's WhatsApp connection
// --------------------------------------------------

async function startWhatsApp(state) {
  if (state.started && state.socket) {
    return;
  }

  if (state.startupPromise) {
    return state.startupPromise;
  }

  state.manuallyDisconnected = false;
  state.started = true;
  state.connected = false;
  state.qr = null;
  state.connectionError = null;

  const startupPromise = (async () => {
    let sock = null;

    try {
      // Credentials are isolated by user.
      fs.mkdirSync(state.authDir, { recursive: true });

      console.log(
        `Starting WhatsApp connection for ${state.email}...`
      );

      const { state: authState, saveCreds } =
        await useMultiFileAuthState(state.authDir);

      const { version } = await fetchLatestBaileysVersion();

      // The user might have disconnected while startup was awaiting.
      if (state.manuallyDisconnected) {
        state.started = false;
        return;
      }

      sock = makeWASocket({
        logger: P({ level: "silent" }),
        printQRInTerminal: false,
        auth: authState,
        version,
        connectTimeoutMs: 60000,
        defaultQueryTimeoutMs: 60000,
        keepAliveIntervalMs: 25000,
        markOnlineOnConnect: false,
      });

      state.socket = sock;

      sock.ev.on("creds.update", () => {
        saveCreds().catch((err) => {
          console.error(
            `Credential save error for ${state.email}:`,
            err.message
          );
        });
      });

      sock.ev.on("connection.update", (update) => {
        // Ignore events from a socket that no longer belongs to this user.
        if (state.socket !== sock) {
          return;
        }

        const { connection, qr, lastDisconnect } = update;

        if (qr) {
          state.qr = qr;
          state.connectionError = null;

          console.log(`New WhatsApp QR available for ${state.email}.`);
        }

        if (connection === "connecting") {
          state.connected = false;
          console.log(`Connecting WhatsApp for ${state.email}...`);
        }

        if (connection === "open") {
          state.qr = null;
          state.connected = true;
          state.started = true;
          state.connectionError = null;

          clearReconnectTimer(state);

          console.log(`WhatsApp connected for ${state.email}.`);
        }

        if (connection === "close") {
          const statusCode =
            lastDisconnect?.error?.output?.statusCode;

          const errorMessage =
            lastDisconnect?.error?.message ||
            "Unknown connection error";

          state.connected = false;
          state.qr = null;
          state.started = false;
          state.socket = null;

          console.error(
            `WhatsApp connection closed for ${state.email}.`,
            "Status:",
            statusCode || "unknown",
            "Error:",
            errorMessage
          );

          if (state.manuallyDisconnected) {
            return;
          }

          const sessionRejected =
            statusCode === 401 ||
            statusCode === DisconnectReason.loggedOut;

          if (sessionRejected) {
            state.connectionError =
              "WhatsApp rejected this user's saved session. " +
              "The authentication files were preserved.";

            console.error(
              `${state.connectionError} User: ${state.email}`
            );

            // Do not repeatedly retry a rejected session.
            return;
          }

          state.connectionError =
            `WhatsApp disconnected (${statusCode || "unknown status"}).`;

          scheduleWhatsAppReconnect(state);
        }
      });
    } catch (err) {
      if (!sock || state.socket === sock) {
        state.socket = null;
        state.started = false;
        state.connected = false;
        state.qr = null;
      }

      state.connectionError =
        err?.message || "Could not start WhatsApp.";

      console.error(
        `WhatsApp startup error for ${state.email}:`,
        err
      );

      if (!state.manuallyDisconnected) {
        scheduleWhatsAppReconnect(state);
      }

      throw err;
    }
  })();

  state.startupPromise = startupPromise;

  try {
    await startupPromise;
  } finally {
    if (state.startupPromise === startupPromise) {
      state.startupPromise = null;
    }
  }
}

// --------------------------------------------------
// Start WhatsApp endpoint
// --------------------------------------------------

app.post("/api/start-whatsapp", requireAuth, async (req, res) => {
  const email = req.session.user.email;
  const state = getWhatsAppState(email);

  try {
    if (state.connected && state.socket) {
      return res.json({
        success: true,
        connected: true,
        message: "Your WhatsApp is already connected.",
      });
    }

    clearReconnectTimer(state);

    if (
      state.connectionError &&
      /rejected this user's saved session/i.test(state.connectionError)
    ) {
      return res.status(409).json({
        success: false,
        connected: false,
        error: state.connectionError,
        message:
          "Back up this user's session folder before troubleshooting authentication.",
      });
    }

    await startWhatsApp(state);

    return res.json({
      success: true,
      connected: state.connected,
      whatsappStarted: state.started,
      qrAvailable: Boolean(state.qr),
      message: state.connected
        ? "Your WhatsApp is connected."
        : "Your connection attempt started. Wait for your QR code.",
    });
  } catch (err) {
    console.error(`Start WhatsApp error for ${email}:`, err);

    return res.status(500).json({
      success: false,
      connected: false,
      error: "Failed to start your WhatsApp connection.",
    });
  }
});

// --------------------------------------------------
// Disconnect only the logged-in user's WhatsApp
// --------------------------------------------------

app.post(
  "/api/disconnect-whatsapp",
  requireAuth,
  (req, res) => {
    const state = getWhatsAppState(req.session.user.email);

    state.manuallyDisconnected = true;
    clearReconnectTimer(state);

    const sock = state.socket;

    // Clear the state before ending the socket so its events are ignored.
    state.socket = null;
    state.connected = false;
    state.started = false;
    state.qr = null;
    state.connectionError = null;

    if (sock) {
      try {
        // Preserve the user's credentials; do not log out.
        sock.end(new Error("Manual disconnect"));

        console.log(
          `WhatsApp temporarily disconnected for ${state.email}.`
        );
      } catch (err) {
        console.error(
          `WhatsApp disconnect error for ${state.email}:`,
          err
        );

        return res.status(500).json({
          success: false,
          connected: false,
          error: "Could not disconnect your WhatsApp.",
        });
      }
    }

    return res.json({
      success: true,
      connected: false,
      message:
        "Your WhatsApp was disconnected without logging out. Your credentials were preserved.",
    });
  }
);

// --------------------------------------------------
// QR endpoint — returns this user's QR as a PNG data URL
// --------------------------------------------------

app.get("/api/whatsapp-qr", requireAuth, async (req, res) => {
  res.set("Cache-Control", "no-store");

  const state = getWhatsAppState(req.session.user.email);

  if (state.connected) {
    return res.json({
      connected: true,
      qrAvailable: false,
      message: "Your WhatsApp is already connected.",
    });
  }

  if (!state.qr) {
    return res.status(404).json({
      connected: false,
      qrAvailable: false,
      whatsappStarted: state.started,
      error:
        state.connectionError ||
        (state.started
          ? "Your QR code is not available yet. Try again shortly."
          : "Your WhatsApp connection has not started."),
    });
  }

  try {
    const qrText = state.qr;

    const qrImage = await QRCode.toDataURL(qrText, {
      type: "image/png",
      width: 280,
      margin: 2,
      errorCorrectionLevel: "M",
    });

    // Verify the QR still belongs to the current connection.
    if (state.connected) {
      return res.json({
        connected: true,
        qrAvailable: false,
        message: "Your WhatsApp is already connected.",
      });
    }

    if (state.qr !== qrText) {
      if (!state.qr) {
        return res.status(404).json({
          connected: false,
          qrAvailable: false,
          error: "Your QR code changed. Please try again.",
        });
      }

      const latestQrImage = await QRCode.toDataURL(state.qr, {
        type: "image/png",
        width: 280,
        margin: 2,
        errorCorrectionLevel: "M",
      });

      return res.json({
        connected: false,
        qrAvailable: true,
        qr: latestQrImage,
      });
    }

    return res.json({
      connected: false,
      qrAvailable: true,
      qr: qrImage,
    });
  } catch (err) {
    console.error(`QR generation error for ${state.email}:`, err);

    return res.status(500).json({
      connected: false,
      qrAvailable: false,
      error: "Could not generate your WhatsApp QR image.",
    });
  }
});

// --------------------------------------------------
// Phone number normalization
// --------------------------------------------------

function normalizeRecipient(input) {
  if (typeof input !== "string") {
    throw new Error("Each recipient must be a phone-number string.");
  }

  const value = input.trim();

  if (!value) {
    throw new Error("A recipient phone number cannot be empty.");
  }

  if (value.endsWith("@s.whatsapp.net")) {
    const phone = value.slice(0, -"@s.whatsapp.net".length);

    if (!/^\d{7,15}$/.test(phone)) {
      throw new Error(`Invalid WhatsApp recipient: ${value}`);
    }

    return `${phone}@s.whatsapp.net`;
  }

  const phone = value.replace(/[\s()+.-]/g, "");

  if (!/^\d{7,15}$/.test(phone)) {
    throw new Error(
      `Invalid phone number: ${value}. ` +
      "Use the full international number with country code."
    );
  }

  return `${phone}@s.whatsapp.net`;
}

// --------------------------------------------------
// Broadcast messages through the correct user's socket
// --------------------------------------------------

async function broadcastMessage(state, sock, message, jids) {
  const sent = [];
  const failed = [];

  for (const jid of jids) {
    // Never continue sending if this user's socket has changed.
    if (
      state.socket !== sock ||
      !state.connected ||
      state.manuallyDisconnected
    ) {
      failed.push({
        jid,
        statusCode: null,
        error: "Your WhatsApp connection was disconnected.",
      });

      break;
    }

    try {
      await sock.sendMessage(jid, { text: message });
      sent.push(jid);

      console.log(
        `Message submitted for ${state.email} to ${jid}`
      );
    } catch (err) {
      const statusCode = err?.output?.statusCode;

      failed.push({
        jid,
        statusCode: statusCode || null,
        error: err?.message || "Unknown send error",
      });

      console.error(
        `Message failed for ${state.email} to ${jid}:`,
        err
      );

      break;
    }
  }

  return { sent, failed };
}

app.post("/send-broadcast", requireAuth, async (req, res) => {
  const email = req.session.user.email;
  const state = getWhatsAppState(email);

  if (!state.connected || !state.socket) {
    return res.status(503).json({
      error:
        "Your WhatsApp is not connected. Link your WhatsApp account and try again.",
    });
  }

  const { message, numbers } = req.body || {};

  if (
    typeof message !== "string" ||
    !message.trim() ||
    !Array.isArray(numbers) ||
    numbers.length === 0
  ) {
    return res.status(400).json({
      error: "A message and at least one phone number are required.",
    });
  }

  if (numbers.length > 100) {
    return res.status(400).json({
      error: "A maximum of 100 recipients is allowed per request.",
    });
  }

  if (
    numbers.some(
      (num) => typeof num !== "string" || !num.trim()
    )
  ) {
    return res.status(400).json({
      error: "Every phone number must be a non-empty string.",
    });
  }

  let jids;

  try {
    jids = [...new Set(numbers.map(normalizeRecipient))];
  } catch (err) {
    return res.status(400).json({
      error: err.message,
    });
  }

  if (jids.length === 0) {
    return res.status(400).json({
      error: "No valid recipient phone numbers were provided.",
    });
  }

  const cleanMessage = message.trim();
  const activeSocket = state.socket;

  console.log(
    `Starting broadcast for ${email}. ` +
    `Unique recipients: ${jids.length}`
  );

  try {
    const result = await broadcastMessage(
      state,
      activeSocket,
      cleanMessage,
      jids
    );

    if (result.failed.length > 0) {
      const failure = result.failed[0];
      const timedOut = failure.statusCode === 408;

      saveLog(email, cleanMessage, numbers, "failed", {
        sentCount: result.sent.length,
        failedCount: result.failed.length,
        error: failure.error,
        statusCode: failure.statusCode,
      });

      return res.status(timedOut ? 504 : 502).json({
        success: false,
        error: timedOut
          ? "WhatsApp timed out while sending. Some recipients may already have received the message."
          : "WhatsApp could not send to a recipient. Some recipients may already have received the message.",
        sentTo: result.sent.length,
        failedAt: failure.jid,
        failedCount: result.failed.length,
        details: failure.error,
      });
    }

    saveLog(email, cleanMessage, numbers, "success", {
      sentCount: result.sent.length,
      failedCount: 0,
    });

    return res.json({
      success: true,
      message: "Broadcast completed.",
      sentTo: result.sent.length,
    });
  } catch (err) {
    const statusCode = err?.output?.statusCode;
    const timedOut = statusCode === 408;

    console.error(`Broadcast error for ${email}:`, err);

    saveLog(email, cleanMessage, numbers, "failed", {
      error: err?.message || "Unknown broadcast error",
      statusCode: statusCode || null,
    });

    return res.status(timedOut ? 504 : 502).json({
      error: timedOut
        ? "WhatsApp timed out while processing the broadcast. Check the connection before retrying."
        : "Failed to send broadcast.",
      details: err?.message || "Unknown broadcast error",
    });
  }
});

// --------------------------------------------------
// Logs endpoint — each user sees only their own logs
// --------------------------------------------------

app.get("/api/logs", requireAuth, (req, res) => {
  try {
    const logs = loadLogs();
    const email = req.session.user.email;

    return res.json(logs[email] || []);
  } catch (err) {
    console.error("Load logs error:", err);

    return res.status(500).json({
      error: "Could not load logs.",
    });
  }
});

// --------------------------------------------------
// Status endpoint — reports only the logged-in user's connection
// --------------------------------------------------

app.get("/status", (req, res) => {
  res.set("Cache-Control", "no-store");

  const email = req.session?.user?.email;

  if (!email) {
    return res.json({
      loggedIn: false,
      connected: false,
      whatsappStarted: false,
      qrAvailable: false,
    });
  }

  let user;

  try {
    const users = loadUsers();
    user = users[email];
  } catch (err) {
    console.error("Status lookup error:", err);

    return res.status(500).json({
      error: "Could not load account status.",
    });
  }

  const expiration = new Date(user?.sessionExpires);

  if (
    !user ||
    !user.isActive ||
    !user.sessionExpires ||
    Number.isNaN(expiration.getTime()) ||
    expiration < new Date()
  ) {
    return res.json({
      loggedIn: false,
      connected: false,
      whatsappStarted: false,
      qrAvailable: false,
    });
  }

  const state = getWhatsAppState(email);

  return res.json({
    loggedIn: true,
    email,
    connected: state.connected,
    whatsappStarted: state.started,
    qrAvailable: Boolean(state.qr),
    ...(state.connectionError
      ? { connectionError: state.connectionError }
      : {}),
  });
});

// --------------------------------------------------
// General error handler
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error("Unhandled request error:", err);

  if (res.headersSent) {
    return next(err);
  }

  if (err.message === "Origin is not allowed by CORS.") {
    return res.status(403).json({
      error: "This frontend origin is not allowed.",
    });
  }

  return res.status(500).json({
    error: "An unexpected server error occurred.",
  });
});

// --------------------------------------------------
// Start server
// --------------------------------------------------

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Per-user WhatsApp sessions enabled.");
  console.log("Local frontend origins allowed:");
  console.log(" - http://127.0.0.1:5500");
  console.log(" - http://localhost:5500");
  console.log(" - http://127.0.0.1:5501");
  console.log(" - http://localhost:5501");
});

// --------------------------------------------------
// Graceful shutdown — close every user's socket
// --------------------------------------------------

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`${signal} received. Shutting down...`);

  for (const state of whatsappConnections.values()) {
    state.manuallyDisconnected = true;
    clearReconnectTimer(state);

    const sock = state.socket;

    state.socket = null;
    state.connected = false;
    state.started = false;
    state.qr = null;

    if (sock) {
      try {
        // Preserve credentials; do not log out or delete session folders.
        sock.end(new Error("Server shutting down"));
      } catch (err) {
        console.error(
          `Error closing socket for ${state.email}:`,
          err.message
        );
      }
    }
  }

  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });

  setTimeout(() => {
    console.error("Shutdown timed out; forcing exit.");
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
