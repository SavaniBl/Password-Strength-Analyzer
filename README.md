# Password-Strength-Analyzer
Checks password strength via entropy, pattern detection, and HaveIBeenPwned API.

# Execution
Secure prompt (password hidden while typing)
python3 password_analyzer.py

Pass directly (visible in shell history)
python3 password_analyzer.py "MyP@ssw0rd!"

Skip HIBP check (offline use)
python3 password_analyzer.py --no-hibp "MyP@ssw0rd!"

JSON output (for scripting/pipelines)
python3 password_analyzer.py --json "MyP@ssw0rd!" | jq .score

Show password in report
python3 password_analyzer.py --show "MyP@ssw0rd!"
