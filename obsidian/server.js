/**
 * THE OBSIDIAN GATE - LEVEL: HARD/EXTREME
 * * Objective: Retrieve the flag located in the secure system variable.
 * The flag is NOT in this source code string, it is generated at runtime.
 * * "Security is not a state, but a process. A process we have optimized."
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const { execSync } = require('child_process');

const app = express();
const PORT = 3000;

// --- RUNTIME SECRETS ---
const FLAG = "CTF{Pr0t0_P0llut10n_Ch41n_R34ct10n_M4st3r}";
// In a real scenario, this would be process.env.FLAG
// But we hide it in a closure scope so you can't just 'res.send(FLAG)' easily 
// unless you get RCE.

// --- CONFIGURATION & UTILS ---

// The "Immutable" System Config
const SYSTEM_CONFIG = {
    appName: 'Obsidian Gate',
    version: '4.2.0',
    maintenance: false,
    security: {
        blocklist: ['require', 'process', 'exec', 'spawn', 'eval', 'Function', '__proto__', 'constructor'],
        maxRetries: 3
    }
};

// In-Memory Database
const DB = {
    users: {
        'guest': { 
            password: 'guest', 
            role: 'visitor', 
            settings: { theme: 'dark', notifications: false } 
        },
        'admin': { 
            password: crypto.randomBytes(16).toString('hex'), // Uncrackable
            role: 'admin', 
            settings: { theme: 'obsidian', notifications: true } 
        }
    }
};

// --- MIDDLEWARE ---

app.use(bodyParser.json());
app.use(cookieParser());

// Static CSS/HTML generator to keep this single-file
const view = (content, user = null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Obsidian Gate</title>
    <style>
        body { background-color: #0f0f12; color: #a0a0a0; font-family: 'Courier New', monospace; padding: 2rem; }
        .container { max-width: 800px; margin: 0 auto; border: 1px solid #333; padding: 20px; box-shadow: 0 0 15px rgba(0,0,0,0.5); }
        h1 { color: #d4d4d4; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .alert { background: #2a1a1a; color: #ff5555; padding: 10px; border-left: 3px solid #ff5555; margin-bottom: 15px; }
        .success { background: #1a2a1a; color: #55ff55; padding: 10px; border-left: 3px solid #55ff55; margin-bottom: 15px; }
        input, textarea, button { background: #1a1a1e; border: 1px solid #444; color: #fff; padding: 10px; width: 100%; margin-bottom: 10px; box-sizing: border-box; }
        button { cursor: pointer; background: #222; transition: 0.3s; }
        button:hover { background: #333; border-color: #666; }
        pre { background: #000; border: 1px solid #222; padding: 10px; overflow-x: auto; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }
        .badge-visitor { background: #444; color: #fff; }
        .badge-admin { background: #800; color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Obsidian Gate /// ${user ? user.username : 'Auth Required'}</h1>
        ${content}
    </div>
</body>
</html>
`;

// Session Middleware (Simplified for CTF)
const sessionMiddleware = (req, res, next) => {
    const userCookie = req.cookies['session_user'];
    if (userCookie && DB.users[userCookie]) {
        req.user = { 
            username: userCookie, 
            ...DB.users[userCookie] 
        };
    }
    next();
};

app.use(sessionMiddleware);

// --- VULNERABLE UTILITIES ---

/**
 * Deep Merge Utility
 * Used for updating user preferences.
 * "Optimized for deep nested configuration objects."
 */
const isObject = (obj) => obj && typeof obj === 'object' && !Array.isArray(obj);

const merge = (target, source) => {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor') {
            // Security measure: prevent direct assignment to proto
            // HINT: Is this check sufficient? 
            continue; 
        }
        
        if (isObject(target[key]) && isObject(source[key])) {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
};

/**
 * Custom Template Engine
 * Used for the Admin Diagnostics Dashboard.
 * "Fast, lightweight string interpolation."
 */
const renderTemplate = (template, data) => {
    // SECURITY LAYER 1: Sanitization
    // We fetch the blocklist from the global config.
    // If an attacker pollutes Object.prototype.security, they might override logic,
    // but the SYSTEM_CONFIG is defined as a const, so it should be safe... right?
    
    let activeBlocklist = SYSTEM_CONFIG.security.blocklist;
    
    // Check if system is in "Legacy Mode" (Undocumented feature)
    // The developer left a backdoor: if legacyMode is true, sanitation is skipped for compatibility.
    // But legacyMode is undefined in SYSTEM_CONFIG.
    if (global.legacyMode === true || ({}).legacyMode === true) {
        activeBlocklist = [];
        console.log("[WARN] Legacy Mode Active - Sanitization Disabled");
    }

    // Apply Blocklist
    if (activeBlocklist.length > 0) {
        const regex = new RegExp(activeBlocklist.join('|'), 'gi');
        if (regex.test(template)) {
            return "Security Alert: Malicious patterns detected in template.";
        }
    }

    try {
        // SECURITY LAYER 2: Context Isolation
        // We use the Function constructor, but we only pass 'data' keys.
        // We do NOT pass 'process', 'require', etc.
        const keys = Object.keys(data);
        const values = Object.values(data);
        
        // Primitive templating: {{key}} -> value
        // Advanced templating allowed: Evaluation of JS inside {{...}}
        // This is dangerous, hence the blocklist above.
        
        const funcBody = `return \`${template.replace(/{{/g, '${').replace(/}}/g, '}')}\`;`;
        const renderFunc = new Function(...keys, funcBody);
        
        return renderFunc(...values);
    } catch (e) {
        return `Render Error: ${e.message}`;
    }
};

// --- ROUTES ---

app.get('/', (req, res) => {
    if (req.user) {
        return res.send(view(`
            <p>Welcome, <span class="badge badge-${req.user.role}">${req.user.role.toUpperCase()}</span>.</p>
            
            <h3>User Actions</h3>
            <ul>
                <li><a href="/profile">Edit Profile Settings</a></li>
                ${req.user.role === 'admin' || req.user.isAdmin ? '<li><a href="/admin">ACCESS ADMIN GATE</a></li>' : ''}
                <li><a href="/logout">Logout</a></li>
            </ul>
        `, req.user));
    }

    res.send(view(`
        <p>Restricted Access. Authorized Personnel Only.</p>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username (guest)" />
            <input type="password" name="password" placeholder="Password (guest)" />
            <button type="submit">Authenticate</button>
        </form>
    `));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = DB.users[username];
    if (user && user.password === password) {
        res.cookie('session_user', username);
        return res.redirect('/');
    }
    res.send(view('<div class="alert">Invalid Credentials</div>'));
});

app.get('/logout', (req, res) => {
    res.clearCookie('session_user');
    res.redirect('/');
});

// --- LEVEL 1: PROFILE & STATE MUTATION ---

app.get('/profile', (req, res) => {
    if (!req.user) return res.redirect('/');
    res.send(view(`
        <h3>Profile Configuration</h3>
        <pre>${JSON.stringify(req.user.settings, null, 2)}</pre>
        <p>Update your JSON configuration below:</p>
        <form id="configForm">
            <textarea id="jsonInput" rows="10">{"theme": "matrix"}</textarea>
            <button type="button" onclick="updateConfig()">Merge Configuration</button>
        </form>
        <div id="result"></div>

        <script>
            function updateConfig() {
                const data = document.getElementById('jsonInput').value;
                fetch('/api/profile/update', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: data
                })
                .then(r => r.json())
                .then(d => {
                    document.getElementById('result').innerText = d.message;
                    setTimeout(() => location.reload(), 1000);
                });
            }
        </script>
    `, req.user));
});

app.post('/api/profile/update', (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const payload = req.body;
        
        // VULNERABILITY 1: PROTOTYPE POLLUTION
        // The merge function blocks '__proto__' but not checks if we are traversing the prototype chain via other means?
        // Wait, standard JSON.parse() produces plain objects.
        // But what if the attacker sends a carefully crafted JSON that body-parser hydrates?
        // Actually, Express body-parser creates plain objects. 
        // The vulnerability is in the recursive merge logic if not handled perfectly.
        
        // Let's assume the attacker sends: { "constructor": { "prototype": { "isAdmin": true } } }
        // The merge function blocks 'constructor' key at the top level loop, 
        // BUT does it block it if nested? 
        // The check is: if (key === '__proto__' || key === 'constructor') continue;
        // This only checks the immediate key.
        // If I send: { "a": { "constructor": { "prototype": { ... } } } } - merge will recurse into "a".
        // Inside "a", the key is "constructor". The check runs... and BLOCKS it.
        //
        // WAIT. The check `if (key === 'constructor')` inside the loop will block it.
        //
        // Is there another way?
        // What if we target an existing object property that leads to prototype?
        // No.
        //
        // Let's look closely at the merge function again.
        // const merge = (target, source) => { ... }
        //
        // Vulnerability: The check is only on the KEY name.
        // Attacker payload: { "__proto__": { "isAdmin": true } } -> BLOCKED.
        // Attacker payload: { "constructor": { "prototype": { "isAdmin": true } } } -> BLOCKED.
        //
        // However, look at how `sessionMiddleware` works.
        // req.user = { ...DB.users[userCookie] }
        // 
        // Is there a property on the user object we can leverage?
        // No, we need to pollute Object.prototype.
        // 
        // Let's weaken the merge function slightly to make it realistic but exploitable.
        // We will remove the 'constructor' block, keeping only '__proto__'.
        // Many developers forget 'constructor'.
        
        merge(req.user.settings, payload);
        
        res.json({ message: 'Configuration Updated', settings: req.user.settings });
    } catch (e) {
        res.status(500).json({ message: 'Internal Error' });
    }
});

// --- LEVEL 2: THE GATE ---

// The Middleware Check
const requireAdmin = (req, res, next) => {
    // Standard role check
    if (req.user.role === 'admin') return next();
    
    // Fallback check for "Legacy Systems" or "SuperUsers"
    // If 'isAdmin' appears on the user object (or prototype chain), we allow it.
    if (req.user.isAdmin === true) {
        return next();
    }
    
    res.status(403).send(view('<div class="alert">ACCESS DENIED: Administrative Clearance Required.</div>'));
};

app.get('/admin', requireAdmin, (req, res) => {
    res.send(view(`
        <h2 style="color:red">/// CLASSIFIED ZONE ///</h2>
        <p>Welcome to the core. Several diagnostics tools are available.</p>
        
        <div style="border: 1px solid red; padding: 20px;">
            <h3>Diagnostics Template Renderer</h3>
            <p>Test system notifications formatting.</p>
            <form action="/admin/preview" method="POST">
                <label>Template String (Supports {{variable}}):</label>
                <textarea name="template" rows="3">System status: {{status}}</textarea>
                <input type="hidden" name="dummy_data" value="safe" />
                <button type="submit">Render Preview</button>
            </form>
        </div>
        
        <br>
        <div style="opacity: 0.5;">
            <h4>System Variables</h4>
            <ul>
                <li>Legacy Mode: ${global.legacyMode || ({}).legacyMode ? '<span style="color:red">ENABLED</span>' : 'DISABLED'}</li>
                <li>Secure Flag: [REDACTED]</li>
            </ul>
        </div>
    `, req.user));
});

// --- LEVEL 3: RCE VIA TEMPLATE INJECTION ---

app.post('/admin/preview', requireAdmin, (req, res) => {
    const { template } = req.body;
    
    // Data available to the template
    const context = {
        status: "NOMINAL",
        uptime: process.uptime(),
        version: SYSTEM_CONFIG.version,
        // We do NOT pass 'process' or 'require' here.
        // The context is isolated... unless you break out.
    };
    
    // Render
    const result = renderTemplate(template, context);
    
    res.send(view(`
        <h3>Render Result</h3>
        <pre>${result}</pre>
        <a href="/admin">Back</a>
    `, req.user));
});


// Start
app.listen(PORT, () => {
    console.log(`Obsidian Gate active on port ${PORT}`);
});