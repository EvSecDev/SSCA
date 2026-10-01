#!/usr/bin/env python3
"""
SSCA Signing Bridge for GPG

What this does:
  Listens for HTTP requests on your local machine (localhost only).
  When it receives a request with the correct token and a block of text (a git commit),
  it asks your GPG key (on your YubiKey) to sign it, and returns the signature.

  That's all it does. It does not:
    - Store any data
    - Connect to the internet
    - Read or write any files
    - Export your private key
    - Do anything with your key except ask it to sign

Setup:
  1. Generate a token: openssl rand -hex 32
  2. Export three environment variables:
       SSCA_SIGN_TOKEN  = the token from step 1
       SSCA_SIGN_KEY    = your GPG key fingerprint
  3. Run: ./ssca-gpg-bridge.py
  4. In the SSCA web UI, enter the same token and your key fingerprint.

The token (SSCA_SIGN_TOKEN):
  A random string that you generate once.
  It is the only thing that prevents other programs on your computer from using this signing service.
  The SSCA web app sends it with every request; this script checks it matches before signing anything.
  If you lose it or think it has been compromised, generate a new one and update both places.
"""
import http.server
import subprocess
import os
import hmac
import shutil
import threading
import sys

# Configuration (from environment variables)

# The shared secret.
# You generate this with `openssl rand -hex 32`.
# The SSCA web app sends it with every request. We check it matches.
TOKEN = os.environ.get("SSCA_SIGN_TOKEN", "")

# Your GPG key fingerprint (the long hex string).
# This tells gpg which key to sign with.
KEY = os.environ.get("SSCA_SIGN_KEY", "")

# Pre-startup checks (fail fast, before listening)

def die(msg, hint=""):
    print(f"ERROR: {msg}", file=sys.stderr)
    if hint:
        print(f"  hint: {hint}", file=sys.stderr)
    sys.exit(1)

# Is gpg installed?
gpg_path = shutil.which("gpg")
if not gpg_path:
    die("gpg not found on PATH", "install gnupg (e.g. `sudo apt install gnupg`)")

# Is the token set?
if not TOKEN:
    die("SSCA_SIGN_TOKEN is not set", "generate one with: openssl rand -hex 32 (then register with UI)")

# Is the key set?
if not KEY:
    die("SSCA_SIGN_KEY is not set", "set your GPG key fingerprint")

# Is the key actually in the keyring?
try:
    r = subprocess.run(
        ["gpg", "--list-keys", "--fingerprint", KEY],
        capture_output=True, timeout=10,
    )
    if r.returncode != 0:
        die(f"GPG key not found in keyring: {KEY[:16]}...",
            "run `gpg --list-keys` to see your keys")
except Exception as e:
    die(f"failed to check GPG keyring: {e}")

# Startup banner
print("SSCA Signing Bridge")
print(f"  listening:  127.0.0.1:1114  [::1]:1114")
print(f"  sign key:   {KEY[:16]}...{KEY[-8:]}")
print(f"  token:      set ({len(TOKEN)} chars)")
print(f"  gpg:        {gpg_path}")
print()

class Handler(http.server.BaseHTTPRequestHandler):

    # CORS preflight
    # Browsers send this first to check if the real request is allowed.
    # We say yes, and also tell Chrome it is OK to talk to localhost (Chrome's "Private Network Access" rule).
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # The actual signing request
    # The SSCA web app sends:
    #   Authorization: Bearer <your token>
    #   Body: the git commit bytes to sign
    # We check the token, then ask gpg to sign the commit.
    def do_POST(self):
        # Is the token configured?
        if not TOKEN:
            self._respond(500, "ERROR: SSCA_SIGN_TOKEN not set")
            return

        # Check the token from the Authorization header.
        # This is the only gate: if the token does not match, we refuse.
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._respond(401, "UNAUTHORIZED")
            return

        # Constant-time comparison (prevents timing attacks).
        if not hmac.compare_digest(auth[7:], TOKEN):
            self._respond(401, "UNAUTHORIZED")
            return

        # Read the commit bytes from the request body.
        commit = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if not commit:
            self._respond(400, "ERROR: empty body")
            return

        # Is the key configured?
        if not KEY:
            self._respond(500, "ERROR: SSCA_SIGN_KEY not set")
            return

        # Ask gpg to sign the commit.
        # gpg will talk to your YubiKey (via gpg-agent) and may
        # prompt you to tap the key or enter your PIN.
        # The signed output (an armored PGP signature) comes back on stdout.
        try:
            result = subprocess.run(
                ["gpg", "--detach-sign", "--armor",
                 "--local-user", KEY, "--no-tty", "--batch"],
                input=commit.encode(),
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            self._respond(500, "ERROR: gpg timed out")
            return

        if result.returncode != 0:
            self._respond(500, "ERROR: " + result.stderr.decode(errors="replace"))
            return

        # Return the signature.
        self._respond(200, result.stdout.decode())

    # --- Headers that allow the browser to talk to us ---
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        # Chrome requires this header to allow a website to talk to localhost.
        self.send_header("Access-Control-Allow-Private-Network", "true")

    # --- Send a response back to the browser ---
    def _respond(self, code, body):
        self.send_response(code)
        self._cors_headers()
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    # Silence the default request logging.
    def log_message(self, *args):
        pass


# Start the server
# We listen on both IPv4 (127.0.0.1) and IPv6 (::1) localhost, because browsers may resolve "localhost" to either one.
# We do NOT listen on any other address.
PORT=1114
try:
    server_v4 = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
except OSError as e:
    die(f"cannot bind to 127.0.0.1:{PORT}: {e}",
        "is something else already using this port?")

try:
    server_v6 = http.server.ThreadingHTTPServer(("::1", PORT), Handler)
    threading.Thread(target=server_v6.serve_forever, daemon=True).start()
    listen_str = f"127.0.0.1:{PORT}  [::1]:{PORT}"
except OSError:
    listen_str = f"127.0.0.1:{PORT}  (IPv6 unavailable)"

print("  ready. waiting for requests...")
print()
server_v4.serve_forever()
