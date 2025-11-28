const express = require("express");
const bodyParser = require("body-parser");
const { exec } = require("child_process");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware Configuration
// Note: extended: true allows parsing of nested objects and arrays
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Security Configuration
const BLACKLIST = [
  "flag",
  "cat",
  "rm",
  "mv",
  "cp",
  "chmod",
  "chown",
  "wget",
  "curl",
];

/* Security Middleware: The Guardian 
   Ensures no malicious keywords are present in the request ID.
*/
const guardian = (req, res, next) => {
  const artifactId = req.body.id;

  if (!artifactId) {
    return res.status(400).send("Error: Missing Artifact ID.");
  }

  // SECURITY CHECK 1: Length Check
  // We don't want long payloads which might be buffer overflows or complex injections
  if (artifactId.length > 15) {
    return res.status(403).send("Error: ID too long.");
  }

  // SECURITY CHECK 2: Keyword Blacklisting
  // Check if the ID contains any banned words
  for (const word of BLACKLIST) {
    if (artifactId.includes(word)) {
      return res.status(403).send(`Error: Malicious keyword detected: ${word}`);
    }
  }

  next();
};

// Route: Home
app.get("/", (req, res) => {
  res.send(`
        <h1>The Artifact Keeper</h1>
        <p>Welcome to the secure storage. Retrieve public artifacts by ID.</p>
        <form action="/retrieve" method="POST">
            <input type="text" name="id" placeholder="Enter Artifact ID (e.g., welcome.txt)">
            <button type="submit">Retrieve</button>
        </form>
    `);
});

// Route: Retrieve Artifact
// Vulnerable Endpoint
app.post("/retrieve", guardian, (req, res) => {
  const artifactId = req.body.id;

  // Simulate retrieving a file from a subfolder named 'public_artifacts'
  // We use 'echo' to simulate a fetch process for this challenge wrapper
  // In a real app, this might be a database fetch or file read.

  // Developer Note: We use 'cat' internally, but we blacklisted it above so user can't abuse it.
  // We assume artifactId is safe because it passed the Guardian.
  const command = `cat public_artifacts/${artifactId}`;

  console.log(`Executing: ${command}`); // Debugging log

  exec(command, (error, stdout, stderr) => {
    if (error) {
      // Don't leak stderr to user in production, but generic error is fine
      return res
        .status(500)
        .send("Error retrieving artifact or file not found.");
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Create dummy artifact for testing
const fs = require("fs");
if (!fs.existsSync("public_artifacts")) {
  fs.mkdirSync("public_artifacts");
}
fs.writeFileSync(
  "public_artifacts/welcome.txt",
  "Welcome to the Artifact Keeper system."
);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
