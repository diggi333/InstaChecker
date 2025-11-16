# InstaChecker
App for your Instagram followers analyse
```markdown
# InstaChecker 

This single-file script `instachecker.py` now auto-installs the core dependencies (instaloader, rich, questionary)
into the current Python environment automatically and silently if they are missing.

Important security note
- Automatic installation modifies the current Python environment. Run the script inside a virtualenv you control.
- If you do not want automatic installation, install the dependencies yourself before running:
  pip install instaloader rich questionary

Prerequisites
- Python 3.8+

Quick start
1. Clone repo or download single file:
   git clone https://github.com/diggi333/instachecker.git
   cd instachecker

   OR download single file directly:
   curl -L -o instachecker.py https://raw.githubusercontent.com/diggi333/instachecker/main/instachecker.py

2. (Recommended) Create and activate virtualenv:
   python3 -m venv .venv
   source .venv/bin/activate   # macOS / Linux
   .venv\\Scripts\\activate     # Windows PowerShell

3. Run the script (it will auto-install core deps if needed):
   python instachecker.py

Optional features
- To enable encrypted session storage and keyring integration, install:
  pip install cryptography keyring

Usage
- Follow interactive prompts: login, choose target usernames (username / @username / URL), view results, export.

Security reminders
- Do not store your Instagram password in plain text in scripts/cron.
- Prefer running this script in an isolated virtualenv and enable encryption/keyring for better security.
```
