const express = require("express");
const bodyParser = require("body-parser");
const { exec } = require("child_process");
const app = express();

app.use(bodyParser.json());
const PORT = 3000;

const db = {
  users: {
    guest: { role: "visitor", theme: "light", notifications: false },
  },
};

const MaintenanceUtils = {
  runDiagnostics: (config) => {
    const cmd = config.diagnosticScript || "date";
    if (config.debugMode) {
      console.log(`[SYSTEM] Running diagnostic: ${cmd}`);
      exec(cmd, (err, stdout, stderr) => {
        if (stdout) {
          console.log(`[OUTPUT] ${stdout.trim()}`);
        }
        if (stderr) {
          console.log(`[ERROR] ${stderr.trim()}`);
        }
      });
    }
  },
};

const merge = (target, source) => {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) {
          target[key] = {};
        }
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
};

const secureSanitizer = (req, res, next) => {
  const bodyStr = JSON.stringify(req.body);
  if (bodyStr.includes("__proto__")) {
    return res
      .status(403)
      .json({ error: "Malicious input detected: __proto__ is forbidden." });
  }
  next();
};

app.get("/", (req, res) => {
  res.send(`
        <h1>Chameleon Registry</h1>
        <p>POST JSON to /api/update-profile to update settings.</p>
        <p>GET /api/health to trigger diagnostics.</p>
    `);
});

app.post("/api/update-profile", secureSanitizer, (req, res) => {
  const user = db.users["guest"];
  const updates = req.body;
  try {
    merge(user, updates);
    res.json({ status: "success", message: "Profile updated", user: user });
  } catch (e) {
    res.status(500).json({ error: "Update failed" });
  }
});

app.get("/api/health", (req, res) => {
  const systemConfig = {};
  const result = MaintenanceUtils.runDiagnostics(systemConfig);
  res.json({
    status: "Health check initiated check server logs"
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
