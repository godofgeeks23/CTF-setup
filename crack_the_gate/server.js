const express = require("express");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// --- IN-MEMORY DATABASE ---
const USERS = {
  "ctf-player@ctfiitk.org": "correct-password-123", // The target account
};

const FLAG = "CTF{TrU5t_N0_H34d3r5_7728}"; // The secret you want to uncover

// --- RATE LIMITING STORAGE ---
// Format: { "ip_address": { attempts: 0, lockUntil: timestamp } }
const rateLimitStore = {};

const MAX_ATTEMPTS = 3;
const LOCK_TIME = 60 * 1000; // 1 minute

// --- VULNERABLE HELPER FUNCTION ---
// This function determines the client's IP.
// VULNERABILITY: It blindly trusts headers sent by the client.
const getClientIp = (req) => {
  // In a secure app, you should only trust these if behind a configured proxy.
  // Here, we check user-controlled headers first.
  const forwarded = req.headers["x-forwarded-for"];
  const clientIp = req.headers["client-ip"];
  const realIp = req.headers["x-real-ip"];

  if (forwarded) return forwarded.split(",")[0].trim();
  if (clientIp) return clientIp;
  if (realIp) return realIp;

  // Fallback to the actual socket IP (safe)
  return req.socket.remoteAddress;
};

// --- LOGIN ROUTE ---
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const ip = getClientIp(req);
  const now = Date.now();

  // 1. Check Rate Limit
  if (!rateLimitStore[ip]) {
    rateLimitStore[ip] = { attempts: 0, lockUntil: 0 };
  }

  const userStats = rateLimitStore[ip];

  if (userStats.lockUntil > now) {
    const waitTime = Math.ceil((userStats.lockUntil - now) / 1000);
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${waitTime} seconds.`,
      source_ip_detected: ip,
    });
  }

  // 2. Validate Credentials
  if (USERS[email] && USERS[email] === password) {
    // Reset attempts on success
    delete rateLimitStore[ip];
    return res.json({
      success: true,
      message: "Login Successful!",
      flag: FLAG,
    });
  } else {
    // Increment failed attempts
    userStats.attempts += 1;

    // Check if we need to lock
    if (userStats.attempts >= MAX_ATTEMPTS) {
      userStats.lockUntil = now + LOCK_TIME;
      return res.status(429).json({
        error: "Maximum attempts reached. You are locked out.",
        source_ip_detected: ip,
      });
    }

    return res.status(401).json({
      error: "Invalid credentials",
      attempts_remaining: MAX_ATTEMPTS - userStats.attempts,
      source_ip_detected: ip,
    });
  }
});

app.listen(PORT, () => {
  console.log(`CTF Challenge running on http://localhost:${PORT}`);
  console.log(`Target Email: ctf-player@ctfiitk.org`);
});
