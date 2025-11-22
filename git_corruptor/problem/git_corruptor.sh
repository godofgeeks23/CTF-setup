#!/bin/bash
# Setup
mkdir git_ghost_challenge
cd git_ghost_challenge
git init

# 1. Create some noise
echo "This is just a normal project." > readme.md
git add readme.md
git commit -m "Initial commit"

# 2. Add the FLAG (The Secret)
echo "CTF{git_plumbing_mastery_882}" > secret_config.json
git add secret_config.json
git commit -m "Added secret config"

# 3. Delete the FLAG (The cleanup)
git rm secret_config.json
git commit -m "Oops, removed secret"

# 4. Obfuscation Step
# We delete the refs so 'git log' wont work.
# We are leaving the 'objects' directory intact.
rm -rf .git/refs
rm .git/HEAD
rm .git/index
rm .git/logs -rf

# 5. Package it
cd ..
tar -czf git_ghost.tar.gz git_ghost_challenge
echo "[+] Challenge created: git_ghost.tar.gz"