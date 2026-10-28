"""A sample backend for the necessary plugin, written from the integration
guide (doc/integration_guide.md) and the measurement contract alone.

Sample code: one process, everything in memory, its secrets made at start.
A real backend keeps its records in a database and its secrets in a vault.
The section numbers below are the guide's. Run:

    python3 server.py --port 8787 --schema <contract>/report.schema.json

It uses the standard library's HTTP server, `cryptography` for ECDSA and
`jsonschema` for the contract's schema (requirements.txt pins both).
"""
import argparse
import base64
import os
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

SESSION_SECONDS = 600            # sessions: ten minutes (section 1)
KEY_CHALLENGE_SECONDS = 120      # key challenges: two minutes (section 1)
SCAN_CHALLENGE_SECONDS = 60      # scan challenges: 60 seconds (section 2)
CLOCK_WINDOW_SECONDS = 120       # request and step-up proofs (section 3)
REPORT_CLOCK_SECONDS = 90        # a report's collected_at (section 2)
NONCE_KEEP_SECONDS = 600         # request-proof nonces, longer than the window
OPERATION_SCAN_SECONDS = 120     # a scan approves its request for a couple of minutes
PIN_PROOF_SECONDS = 120          # an app PIN proof: about two minutes
PIN_LENGTH = 6                   # this sample's choice of PIN length
PIN_ATTEMPTS = 5                 # this sample's limit of wrong PINs
MAX_REPORT_BYTES = 65536         # the contract's limit
MIN_COLLECTOR = {"android": 8, "ios": 5}   # the contract this sample reads
VERIFIER_ROUNDS = 600_000        # PBKDF2-HMAC-SHA256, a slow verifier

# What this sample asks for in every scan: every measurement that would catch
# tampering, the hooks, gadgets and changes to the app's code in memory among
# them. One left to chance is one a tampered app waits out, scanning again
# until it is not drawn. Only what weighs little varies.
RELIED_ON = {
    "android": ["app_identity", "debug_state", "tracer", "root_files", "root_shell",
                "system_properties", "selinux", "mounts", "developer_settings",
                # Hooks and gadgets by name, by port, by thread and by memory
                # layout; and the code in memory compared with its file.
                "runtime_maps", "frida_ports", "instrumentation_threads",
                "exec_mappings", "code_integrity"],
    "ios": ["app_identity", "code_signing", "debugger", "jailbreak_files", "sandbox",
            # Injected libraries, and the app's code in memory compared with
            # its file -- asked for, so that a report without it is refused.
            "dyld_images", "environment", "code_integrity"],
}
VARIED = {
    "android": ["emulator"],
    "ios": ["simulator"],
}
# The personal measurements (the guide, section 8): this sample asks for every
# one in every scan, so that the example app can show each one it enables. A
# production backend asks only for those it uses.
PERSONAL = ["local_addresses", "accessibility", "notification_access", "other_access",
            "screen_capture", "location", "mock_location"]


# --- Binary values travel as base64url without padding; hashes are hex SHA-256.

def b64url_decode(text):
    if not isinstance(text, str):
        raise ValueError("not base64url text")
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Refusal(Exception):
    """An answer of {"error": {"code", "message", "details"}} (section 4)."""

    def __init__(self, status, code, message, details=None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


# --- Section 1: the installation key (the guide's reference code, section 5).

def public_key(jwk):
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are accepted")
    x, y = b64url_decode(jwk.get("x")), b64url_decode(jwk.get("y"))
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coordinates are 32 bytes each")
    # Raises ValueError for a point that is not on the curve.
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()


def thumbprint(jwk):
    x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
    return sha256_hex(canonical({"crv": "P-256", "kty": "EC",
                                 "x": b64url_encode(x), "y": b64url_encode(y)}))


def verifies(jwk, payload, signature_b64):
    """Whether the signature verifies over these bytes, as they were signed."""
    try:
        public_key(jwk).verify(b64url_decode(signature_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def slow_verifier(secret, subject, value, salt=None):
    """PBKDF2 over an HMAC of the subject and the value, keyed by a secret the
    records never hold: a copy of the records checks nothing."""
    salt = salt or secrets.token_bytes(16)
    keyed = hmac.new(secret, ("%s:%s" % (subject, value)).encode("utf-8"), hashlib.sha256).digest()
    return salt, hashlib.pbkdf2_hmac("sha256", keyed, salt, VERIFIER_ROUNDS)


class Backend:
    def __init__(self, schema, test_token):
        self.validator = jsonschema.Draft202012Validator(schema)
        self.test_token = test_token     # test controls answer only this token
        self.lock = threading.Lock()
        # Secrets made at start: a restart forgets every session and challenge.
        self.challenge_key = secrets.token_bytes(32)
        self.hint_key = secrets.token_bytes(32)
        self.pin_secret = secrets.token_bytes(32)
        self.password_secret = secrets.token_bytes(32)
        self.pin_proof_key = secrets.token_bytes(32)
        self.installations = {}      # installation_id -> record
        self.by_thumbprint = {}      # key thumbprint -> installation_id
        self.used_key_challenges = set()
        self.sessions = {}           # token -> session
        self.nonces = {}             # SHA-256 of a request-proof nonce -> kept until
        self.scan_challenges = {}    # challenge_id -> challenge
        self.reports = {}            # report_id -> stored report
        self.accounts = {}           # handle -> account
        self.pending = {}            # test control: path -> the next request's refusal

    def now(self):
        return int(time.time())

    # --- Section 1: registration.

    def register(self, body):
        installation_id, platform = body.get("installation_id"), body.get("platform")
        try:
            uuid.UUID(str(installation_id))
            jwk = body.get("public_key")
            public_key(jwk)
        except ValueError:
            raise Refusal(400, "bad_request", "A UUID and an EC P-256 public key are required.",
                          {"field": "public_key"})
        if platform not in ("android", "ios"):
            raise Refusal(400, "bad_request", "The platform is android or ios.",
                          {"field": "platform"})
        hint = body.get("reinstall_hint")
        if hint is not None and not (
                isinstance(hint, dict) and hint.get("kind") in ("android_id_sha256", "idfv_sha256")
                and isinstance(hint.get("value"), str)
                and re.fullmatch(r"[0-9a-f]{64}", hint["value"])):
            raise Refusal(400, "bad_request", "The reinstall hint is malformed.",
                          {"field": "reinstall_hint"})
        key = thumbprint(jwk)
        step_up = self._step_up_key(body, key)
        with self.lock:
            held = self.by_thumbprint.get(key)
            if held is not None:
                # The thumbprint is the identity: the same key is the same
                # installation, whatever ID it proposes. A step-up key offered
                # now is not taken -- only re-enrolment replaces one.
                return {"installation_id": held}
            if installation_id in self.installations:
                raise Refusal(409, "installation_id_taken",
                              "This installation ID belongs to another key.")
            self.installations[installation_id] = {
                "thumbprint": key, "jwk": jwk, "platform": platform,
                # Keyed before it is kept: what the app says, never proof.
                "hint": (hmac.new(self.hint_key, hint["value"].encode("ascii"),
                                  hashlib.sha256).hexdigest() if hint else None),
                # Recorded, never relied on: the phone cannot prove it.
                "key_security": body.get("key_security"),
                "step_up": step_up,
            }
            self.by_thumbprint[key] = installation_id
        return {"installation_id": installation_id}

    def _step_up_key(self, body, installation_thumbprint):
        """Section 3, step-up: the key and how the phone says it is unlocked."""
        jwk = body.get("stepup_public_key")
        if jwk is None:
            return None
        auth = body.get("stepup_key_auth")
        try:
            public_key(jwk)
        except ValueError:
            raise Refusal(400, "bad_request", "The step-up key is not an EC P-256 key.",
                          {"field": "stepup_public_key"})
        if thumbprint(jwk) == installation_thumbprint:
            raise Refusal(400, "bad_request", "The step-up key must not be the installation key.",
                          {"field": "stepup_public_key"})
        window = auth.get("window_seconds") if isinstance(auth, dict) else None
        if not (isinstance(auth, dict) and auth.get("factor") in ("passcode", "biometric")
                and isinstance(window, int) and not isinstance(window, bool)
                and ((auth.get("mode") == "per_use" and window == 0)
                     or (auth.get("mode") == "windowed" and 1 <= window <= 3600))):
            raise Refusal(400, "bad_request", "stepup_key_auth is malformed.",
                          {"field": "stepup_key_auth"})
        return {"jwk": jwk, "factor": auth["factor"], "mode": auth["mode"],
                "window_seconds": window}

    # --- Section 1: proof of possession, with a challenge that stores nothing.

    def key_challenge(self, body):
        installation_id = body.get("installation_id")
        with self.lock:
            if installation_id not in self.installations:
                raise Refusal(404, "installation_not_found", "No such installation.")
        expires = self.now() + KEY_CHALLENGE_SECONDS
        claims = {"challenge_id": str(uuid.uuid4()), "installation_id": installation_id,
                  "purpose": "prove_installation", "nonce": b64url_encode(secrets.token_bytes(32)),
                  "expires_at": expires}
        claims["mac"] = b64url_encode(hmac.new(self.challenge_key, canonical(claims),
                                               hashlib.sha256).digest())
        return {"challenge_id": claims["challenge_id"],
                "payload": b64url_encode(canonical(claims)), "expires_at": iso(expires)}

    def verify(self, body):
        installation_id, challenge_id = body.get("installation_id"), body.get("challenge_id")
        try:
            payload = b64url_decode(body.get("payload"))
            claims = json.loads(payload.decode("utf-8"))
            mac = b64url_decode(claims.pop("mac"))
        except (ValueError, KeyError, AttributeError, UnicodeDecodeError):
            raise Refusal(401, "proof_not_accepted", "This is not a challenge of ours.")
        expected = hmac.new(self.challenge_key, canonical(claims), hashlib.sha256).digest()
        if (not hmac.compare_digest(mac, expected) or claims.get("challenge_id") != challenge_id
                or claims.get("installation_id") != installation_id
                or claims.get("purpose") != "prove_installation"):
            raise Refusal(401, "proof_not_accepted", "This is not a challenge of ours.")
        if claims["expires_at"] < self.now():
            raise Refusal(401, "challenge_expired", "The challenge has expired.")
        with self.lock:
            installation = self.installations.get(installation_id)
        if installation is None:
            raise Refusal(404, "installation_not_found", "No such installation.")
        if not verifies(installation["jwk"], payload, body.get("signature")):
            raise Refusal(401, "invalid_installation_signature", "The signature does not verify.")
        with self.lock:
            # Consumed only after the signature verifies, atomically.
            if challenge_id in self.used_key_challenges:
                raise Refusal(401, "challenge_used", "The challenge was answered already.")
            self.used_key_challenges.add(challenge_id)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {"kind": "installation", "installation_id": installation_id,
                                    "expires": self.now() + SESSION_SECONDS}
        return {"device_token": token, "expires_at": iso(self.now() + SESSION_SECONDS)}

    # --- Section 3: every request carries a request proof.

    def authenticate(self, request, kinds):
        """The session and the request proof's nonce, or a refusal."""
        token = request.bearer
        with self.lock:
            session = self.sessions.get(token) if token else None
            installation = (self.installations.get(session["installation_id"])
                            if session else None)
        if session is None or session["kind"] not in kinds:
            raise Refusal(401, "not_signed_in", "This request needs a session of ours.")
        if session["expires"] < self.now():
            raise Refusal(401, "expired_token", "The session has expired.")
        if installation is None:
            raise Refusal(404, "installation_not_found", "No such installation.")
        try:
            raw = b64url_decode(request.headers.get("X-Access-Proof"))
            proof = json.loads(raw.decode("utf-8"))
            nonce = b64url_decode(proof["nonce"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise Refusal(401, "proof_not_accepted", "The request proof is missing or malformed.")
        expected = {
            "access_token_sha256": sha256_hex(token.encode("utf-8")),
            "body_sha256": sha256_hex(request.body),
            "installation_id": session["installation_id"],
            "method": request.method,
            "path": request.path,
            "query": request.query,
            "version": 2,
        }
        for field, value in expected.items():
            if proof.get(field) != value:
                raise Refusal(401, "proof_not_accepted", "The request proof is for another request.",
                              {"check": field})
        timestamp = proof.get("timestamp")
        if (isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or abs(self.now() - timestamp) > CLOCK_WINDOW_SECONDS or len(nonce) != 32):
            raise Refusal(401, "proof_not_accepted", "The request proof is out of time.",
                          {"check": "timestamp"})
        if not verifies(installation["jwk"], raw, request.headers.get("X-Access-Signature")):
            raise Refusal(401, "invalid_installation_signature", "The signature does not verify.")
        key = sha256_hex(nonce)
        with self.lock:
            # Stored only after the signature verifies, under a unique key.
            for kept in [k for k, until in self.nonces.items() if until < self.now()]:
                del self.nonces[kept]
            if key in self.nonces:
                raise Refusal(401, "proof_reused", "This request was sent already.")
            self.nonces[key] = self.now() + NONCE_KEEP_SECONDS
        return session, installation, proof["nonce"]

    # --- Section 2: the scan.

    def scan_challenge(self, request, body):
        session, installation, _ = self.authenticate(request, ("installation", "account"))
        operation = body.get("operation")
        digest = None
        if operation is not None:
            # A scan for one action is the account's, never the installation's.
            if session["kind"] != "account" or not self._operation_valid(operation):
                raise Refusal(400, "invalid_operation",
                              "An operation is named only under an account session, whole.")
            digest = sha256_hex(canonical(operation))
        platform = installation["platform"]
        # Each of the others on about half the scans, unpredictably.
        required = RELIED_ON[platform] + [
            name for name in VARIED[platform] if secrets.randbelow(2)]
        nonce = secrets.token_bytes(32)
        challenge_id = str(uuid.uuid4())
        expires = self.now() + SCAN_CHALLENGE_SECONDS
        with self.lock:
            self.scan_challenges[challenge_id] = {
                "installation_id": session["installation_id"], "platform": platform,
                "nonce_sha256": sha256_hex(nonce), "required": required, "expires": expires,
                "used": False, "operation_sha256": digest,
                "session": request.bearer if digest else None,
            }
        return {"challenge_id": challenge_id, "nonce": b64url_encode(nonce), "platform": platform,
                "required_probes": required, "optional_probes": PERSONAL, "expires_at": iso(expires)}

    @staticmethod
    def _operation_valid(operation):
        return (isinstance(operation, dict) and set(operation) == {"method", "path", "query",
                                                                   "body_sha256"}
                and operation["method"] in ("GET", "POST", "PUT", "PATCH", "DELETE")
                and isinstance(operation["path"], str) and operation["path"].startswith("/")
                and isinstance(operation["query"], str)
                and isinstance(operation["body_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", operation["body_sha256"]) is not None)

    def report(self, request, body):
        session, installation, _ = self.authenticate(request, ("installation", "account"))
        try:
            # 1. Decoded, at most the contract's size, a JSON object of version 1.
            payload = b64url_decode(body.get("report_payload"))
            if len(payload) > MAX_REPORT_BYTES:
                raise ValueError("too large")
            report = json.loads(payload.decode("utf-8"))
            if not isinstance(report, dict) or report.get("version") != 1:
                raise ValueError("version")
        except (ValueError, UnicodeDecodeError) as error:
            raise Refusal(400, "report_not_accepted", "The report is not one we read.",
                          {"check": str(error)})
        # 2. Its installation is the session's.
        if report.get("installation_id") != session["installation_id"]:
            raise Refusal(400, "report_not_accepted", "The report names another installation.",
                          {"check": "installation_id"})
        with self.lock:
            # 3. Its challenge, held while it is checked: this installation's,
            #    for its platform.
            challenge = self.scan_challenges.get(report.get("challenge_id"))
            if (challenge is None or challenge["installation_id"] != session["installation_id"]
                    or report.get("platform") != challenge["platform"]):
                raise Refusal(400, "report_not_accepted", "The report answers no challenge of ours.",
                              {"check": "challenge_id"})
            # 4. Unused and in time.
            if challenge["used"]:
                raise Refusal(401, "integrity_challenge_replay", "The challenge was answered already.")
            if challenge["expires"] < self.now():
                raise Refusal(401, "integrity_challenge_expired", "The challenge has expired.")
            # 5. The nonce it was given.
            try:
                nonce = b64url_decode(report.get("challenge_nonce"))
            except ValueError:
                nonce = b""
            if not hmac.compare_digest(sha256_hex(nonce), challenge["nonce_sha256"]):
                raise Refusal(400, "report_not_accepted", "The report carries another nonce.",
                              {"check": "challenge_nonce"})
            # 6. The phone's clock.
            collected = report.get("collected_at")
            if (isinstance(collected, bool) or not isinstance(collected, int)
                    or abs(self.now() - collected) > REPORT_CLOCK_SECONDS):
                raise Refusal(400, "integrity_report_stale", "The phone's clock is far off.")
            # 7. A collector this backend reads.
            version = report.get("collector_version")
            if (isinstance(version, bool) or not isinstance(version, int)
                    or version < MIN_COLLECTOR[challenge["platform"]]):
                raise Refusal(400, "report_not_accepted", "This collector is too old.",
                              {"check": "collector_version"})
            # 8. Every measurement asked for.
            results = report.get("probe_results")
            missing = [p for p in challenge["required"]
                       if not isinstance(results, dict) or p not in results]
            if missing:
                raise Refusal(400, "integrity_probe_missing", "A measurement asked for is missing.",
                              {"missing_probes": missing})
            # 9. The signature, over the decoded bytes.
            if not verifies(installation["jwk"], payload, body.get("report_signature")):
                raise Refusal(401, "invalid_installation_signature", "The signature does not verify.")
            # 10. Used, in the same unit of work.
            challenge["used"] = True
        # Only then are the measurements read: first, whether they are the
        # contract's.
        problems = sorted(self.validator.iter_errors(report),
                          key=lambda e: list(e.absolute_path))
        if problems:
            raise Refusal(400, "report_not_accepted", "The report is not the contract's.",
                          {"check": "schema", "at": "/".join(map(str, problems[0].absolute_path))})
        report_id = str(uuid.uuid4())
        with self.lock:
            self.reports[report_id] = {
                "installation_id": session["installation_id"], "at": self.now(), "used": False,
                "operation_sha256": challenge["operation_sha256"], "session": challenge["session"],
                "report_sha256": sha256_hex(payload),
            }
        # Your business logic decides; the answer says what to do next, never
        # a score or a reason (section 7).
        return {"integrity": {"report_id": report_id, "next": "allow"}}

    # --- Section 2: a scan for one action, used by the request it named.

    def require_operation_scan(self, request, session):
        report_id = request.headers.get("X-Integrity-Report")
        here = sha256_hex(canonical({"method": request.method, "path": request.path,
                                     "query": request.query,
                                     "body_sha256": sha256_hex(request.body)}))
        with self.lock:
            stored = self.reports.get(report_id or "")
            if (stored is None or stored["used"] or stored["operation_sha256"] != here
                    or stored["session"] != request.bearer
                    or self.now() - stored["at"] > OPERATION_SCAN_SECONDS):
                raise Refusal(403, "needs_scan", "This request needs a scan made for it.")
            stored["used"] = True

    # --- Section 3: step-up.

    def require_step_up(self, request, session, installation, nonce):
        raw_b64 = request.headers.get("X-Step-Up-Proof")
        step_up = installation.get("step_up")
        if not raw_b64 or not request.headers.get("X-Step-Up-Signature") or step_up is None:
            raise Refusal(403, "needs_step_up", "This request needs the person's approval.")
        try:
            raw = b64url_decode(raw_b64)
            proof = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raw, proof = b"", {}
        if not verifies(step_up["jwk"], raw, request.headers.get("X-Step-Up-Signature")):
            raise Refusal(403, "step_up_not_accepted", "The approval does not verify.",
                          {"check": "signature"})
        expected = {
            "version": 2, "purpose": "stepup", "installation_id": session["installation_id"],
            "access_token_sha256": sha256_hex(request.bearer.encode("utf-8")),
            "method": request.method, "path": request.path, "query": request.query,
            "body_sha256": sha256_hex(request.body), "nonce": nonce,
            # The factor this sample requires is the one the key was made with.
            "factor": step_up["factor"],
        }
        for field, value in expected.items():
            if proof.get(field) != value:
                raise Refusal(403, "step_up_not_accepted", "The approval is for another request.",
                              {"check": field})
        timestamp = proof.get("timestamp")
        if (isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or abs(self.now() - timestamp) > CLOCK_WINDOW_SECONDS):
            raise Refusal(403, "step_up_not_accepted", "The approval is out of time.",
                          {"check": "timestamp"})

    # --- Section 3: the app PIN.

    def set_app_pin(self, request, body):
        session, _, _ = self.authenticate(request, ("account",))
        account = self.accounts[session["account"]]
        self._reauthenticate(account, session["account"], body.get("password"))
        pin = body.get("pin")
        if not (isinstance(pin, str) and len(pin) == PIN_LENGTH and pin.isascii() and pin.isdigit()):
            raise Refusal(400, "bad_request", "The PIN is %d digits." % PIN_LENGTH, {"field": "pin"})
        salt, verifier = slow_verifier(self.pin_secret, session["account"], pin)
        with self.lock:
            # A new PIN clears the wrong ones and any lock.
            account.update(pin_salt=salt, pin_verifier=verifier, pin_failures=0, pin_locked=False)
        return {"app_pin_set": True}

    def prove_app_pin(self, request, body):
        session, _, _ = self.authenticate(request, ("account",))
        pin, target = body.get("pin"), body.get("request")
        try:
            complete = (isinstance(pin, str) and pin and self._operation_valid(
                {k: target.get(k) for k in ("method", "path", "query", "body_sha256")})
                and len(b64url_decode(target.get("nonce"))) == 32)
        except (AttributeError, ValueError):
            complete = False
        if not complete:
            # Refused before the PIN is checked.
            raise Refusal(400, "bad_request", "Send the PIN and the request it unlocks.",
                          {"field": "request"})
        account = self.accounts[session["account"]]
        with self.lock:
            if account.get("pin_verifier") is None:
                raise Refusal(403, "app_pin_not_set", "No app PIN is set for this account.")
            if account["pin_locked"]:
                raise Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.")
            if account["pin_failures"] + account["pin_checking"] >= PIN_ATTEMPTS:
                # The attempts left are held by checks still running.
                raise Refusal(429, "pin_busy", "The PIN is being checked; try again in a moment.",
                              {"retry_after_seconds": 1})
            account["pin_checking"] += 1     # the attempt, claimed before comparing
            salt, verifier = account["pin_salt"], account["pin_verifier"]
        right = hmac.compare_digest(
            slow_verifier(self.pin_secret, session["account"], pin, salt)[1], verifier)
        with self.lock:
            account["pin_checking"] -= 1
            if right:
                account["pin_failures"] = 0
            else:
                account["pin_failures"] += 1
                account["pin_locked"] = account["pin_failures"] >= PIN_ATTEMPTS
        if not right:
            if account["pin_locked"]:
                raise Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.")
            raise Refusal(403, "app_pin_invalid", "The app PIN is wrong.")
        expires = self.now() + PIN_PROOF_SECONDS
        claims = canonical({"account": session["account"],
                            "installation_id": session["installation_id"],
                            "session_sha256": sha256_hex(request.bearer.encode("utf-8")),
                            "request": target, "expires_at": expires})
        mac = hmac.new(self.pin_proof_key, claims, hashlib.sha256).digest()
        return {"app_pin_proof": "%s.%s" % (b64url_encode(claims), b64url_encode(mac)),
                "expires_at": iso(expires)}

    def require_app_pin(self, request, session, nonce):
        try:
            encoded, mac = request.headers.get("X-App-PIN-Proof", "").split(".")
            claims = b64url_decode(encoded)
            ours = hmac.compare_digest(
                b64url_decode(mac), hmac.new(self.pin_proof_key, claims, hashlib.sha256).digest())
            proof = json.loads(claims.decode("utf-8")) if ours else None
        except (ValueError, UnicodeDecodeError):
            proof = None
        if proof is None:
            raise Refusal(403, "needs_app_pin", "This request needs the app PIN.")
        expected = {"account": session["account"], "installation_id": session["installation_id"],
                    "session_sha256": sha256_hex(request.bearer.encode("utf-8")),
                    "request": {"method": request.method, "path": request.path,
                                "query": request.query, "body_sha256": sha256_hex(request.body),
                                "nonce": nonce}}
        if proof.get("expires_at", 0) < self.now() or any(
                proof.get(field) != value for field, value in expected.items()):
            raise Refusal(403, "app_pin_not_accepted", "The PIN's proof is for another request.")

    # --- This sample's own account API, in which the plugin's proofs are used.

    def sign_in(self, request, body):
        session, _, _ = self.authenticate(request, ("installation",))
        handle, password = body.get("handle"), body.get("password")
        if not (isinstance(handle, str) and handle and isinstance(password, str) and password):
            raise Refusal(400, "bad_request", "A handle and a password are required.")
        with self.lock:
            account = self.accounts.get(handle)
        if account is None:
            salt, verifier = slow_verifier(self.password_secret, handle, password)
            with self.lock:
                account = self.accounts.setdefault(handle, {
                    "password_salt": salt, "password_verifier": verifier, "pin_salt": None,
                    "pin_verifier": None, "pin_failures": 0, "pin_locked": False,
                    "pin_checking": 0})
        self._reauthenticate(account, handle, password)
        token = secrets.token_urlsafe(32)
        with self.lock:
            # An account session for this installation, which proved its key.
            self.sessions[token] = {"kind": "account", "installation_id": session["installation_id"],
                                    "account": handle, "expires": self.now() + SESSION_SECONDS}
        return {"account_session": token}

    def _reauthenticate(self, account, handle, password):
        _, verifier = slow_verifier(self.password_secret, handle, str(password),
                                    account["password_salt"])
        if not hmac.compare_digest(verifier, account["password_verifier"]):
            raise Refusal(401, "reauthentication_failed", "The password is wrong.")

    def demo(self, request, needs):
        session, installation, nonce = self.authenticate(request, ("account",))
        if "scan" in needs:
            self.require_operation_scan(request, session)
        if "approval" in needs:
            # The person's approval, as the request offers it: step-up, the
            # app PIN, or both -- and each one offered must hold.
            step_up = bool(request.headers.get("X-Step-Up-Proof"))
            app_pin = bool(request.headers.get("X-App-PIN-Proof"))
            if not (step_up or app_pin):
                raise Refusal(403, "needs_approval",
                              "This request needs the person's approval: step-up or the app PIN.")
            if step_up:
                self.require_step_up(request, session, installation, nonce)
            if app_pin:
                self.require_app_pin(request, session, nonce)
        return {"done": request.path}

    # --- Test controls, on only with --test-controls.

    def control(self, path, body):
        with self.lock:
            if path == "/test/expire-sessions":
                for session in self.sessions.values():
                    session["expires"] = self.now() - 1
            elif path == "/test/forget":
                record = self.installations.pop(body.get("installation_id"), None)
                if record is not None:
                    self.by_thumbprint.pop(record["thumbprint"], None)
            elif path == "/test/refuse-next":
                self.pending[body["path"]] = body
            else:
                raise Refusal(404, "no_such_path", "No such control.")
        return {"ok": True}


ROUTES = {
    "/v1/installations/register": lambda b, r, body: b.register(body),
    "/v1/installations/challenge": lambda b, r, body: b.key_challenge(body),
    "/v1/installations/verify": lambda b, r, body: b.verify(body),
    "/v1/integrity/challenge": lambda b, r, body: b.scan_challenge(r, body),
    "/v1/integrity/report": lambda b, r, body: b.report(r, body),
    "/v1/account/app-pin": lambda b, r, body: b.set_app_pin(r, body),
    "/v1/account/app-pin/proof": lambda b, r, body: b.prove_app_pin(r, body),
    "/v1/demo/sign-in": lambda b, r, body: b.sign_in(r, body),
    "/v1/demo/echo": lambda b, r, body: b.demo(r, ()),
    "/v1/demo/transfer": lambda b, r, body: b.demo(r, ("scan",)),
    "/v1/demo/sensitive": lambda b, r, body: b.demo(r, ("approval",)),
}


class Request:
    def __init__(self, handler, body):
        target = urlsplit(handler.path)
        self.method = handler.command
        self.path, self.query = target.path, target.query
        self.headers = handler.headers
        self.body = body
        auth = handler.headers.get("Authorization", "")
        self.bearer = auth[7:] if auth.startswith("Bearer ") else None


def handler_for(backend):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):   # never a request's body or headers: they hold PINs
            pass

        def answer(self, status, value):
            # One line per call: the method, the path, the status and any refusal's code.
            error = value.get("error") if isinstance(value, dict) else None
            print("%s %s %d %s" % (self.command, urlsplit(self.path).path, status,
                                   error["code"] if error else ""), flush=True)
            data = json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if urlsplit(self.path).path == "/health":
                self.answer(200, {"ok": True})
            else:
                self.answer(404, {"error": {"code": "no_such_path", "message": "No such path."}})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1 << 20:
                self.answer(413, {"error": {"code": "too_large", "message": "Too large."}})
                return
            raw = self.rfile.read(length)
            request = Request(self, raw)
            try:
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except ValueError:
                    raise Refusal(400, "bad_request", "The body is not JSON.")
                if not isinstance(body, dict):
                    raise Refusal(400, "bad_request", "The body is not a JSON object.")
                if (request.path.startswith("/test/") and backend.test_token
                        and hmac.compare_digest(self.headers.get("X-Test-Token", "").encode(),
                                                backend.test_token.encode())):
                    self.answer(200, backend.control(request.path, body))
                    return
                with backend.lock:
                    pending = backend.pending.pop(request.path, None)
                if pending is not None:
                    raise Refusal(pending.get("status", 400), pending["code"], "Refused for a test.",
                                  pending.get("details"))
                route = ROUTES.get(request.path)
                if route is None:
                    raise Refusal(404, "no_such_path", "No such path.")
                self.answer(200, route(backend, request, body))
            except Refusal as refusal:
                error = {"code": refusal.code, "message": refusal.message}
                if refusal.details:
                    error["details"] = refusal.details
                self.answer(refusal.status, {"error": error})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--schema", required=True, help="the contract's report.schema.json")
    parser.add_argument("--test-controls", action="store_true",
                        help="answer /test/* (expiring the sessions, forgetting an "
                             "installation, refusing the next request) to requests carrying "
                             "X-Test-Token: $SAMPLE_TEST_TOKEN -- for tests only")
    args = parser.parse_args()
    token = os.environ.get("SAMPLE_TEST_TOKEN", "") if args.test_controls else None
    if token is not None and len(token) < 16:
        parser.error("--test-controls needs SAMPLE_TEST_TOKEN, 16 characters or more")
    with open(args.schema, encoding="utf-8") as handle:
        backend = Backend(json.load(handle), token)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(backend))
    print("listening on http://127.0.0.1:%d" % args.port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
