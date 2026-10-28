// A sample backend for the necessary plugin, written from the integration
// guide (doc/integration_guide.md) and the measurement contract alone.
//
// Sample code: one process, everything in memory, its secrets made at start.
// A real backend keeps its records in a database and its secrets in a vault.
// The section numbers below are the guide's. Run:
//
//     node dist/server.js --port 8787 --schema <contract>/report.schema.json
//
// Node's own HTTP server and crypto, and ajv for the contract's schema.
import Ajv2020 from "ajv/dist/2020";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);

const SESSION_SECONDS = 600; // sessions: ten minutes (section 1)
const KEY_CHALLENGE_SECONDS = 120; // key challenges: two minutes (section 1)
const SCAN_CHALLENGE_SECONDS = 60; // scan challenges: 60 seconds (section 2)
const CLOCK_WINDOW_SECONDS = 120; // request and step-up proofs (section 3)
const REPORT_CLOCK_SECONDS = 90; // a report's collected_at (section 2)
const NONCE_KEEP_SECONDS = 600; // request-proof nonces, longer than the window
const OPERATION_SCAN_SECONDS = 120; // a scan approves its request for a couple of minutes
const PIN_PROOF_SECONDS = 120; // an app PIN proof: about two minutes
const PIN_LENGTH = 6; // this sample's choice of PIN length
const PIN_ATTEMPTS = 5; // this sample's limit of wrong PINs
const MAX_REPORT_BYTES = 65536; // the contract's limit
const MIN_COLLECTOR: Record<string, number> = { android: 8, ios: 5 };
const VERIFIER_ROUNDS = 600_000; // PBKDF2-HMAC-SHA256, a slow verifier

// What this sample asks for in every scan: every measurement that would catch tampering, the hooks,
// gadgets and changes to the app's code in memory among them. One left to chance is one a tampered
// app waits out, scanning again until it is not drawn. Only what weighs little varies.
const RELIED_ON: Record<string, string[]> = {
  android: ["app_identity", "debug_state", "tracer", "root_files", "root_shell", "system_properties",
    "selinux", "mounts", "developer_settings",
    // Hooks and gadgets by name, by port, by thread and by memory layout; and the code in memory
    // compared with its file.
    "runtime_maps", "frida_ports", "instrumentation_threads", "exec_mappings", "code_integrity"],
  ios: ["app_identity", "code_signing", "debugger", "jailbreak_files", "sandbox",
    // Injected libraries, and the app's code in memory compared with its file -- asked for, so
    // that a report without it is refused.
    "dyld_images", "environment", "code_integrity"],
};
const VARIED: Record<string, string[]> = {
  android: ["emulator"],
  ios: ["simulator"],
};
// The personal measurements (the guide, section 8): this sample asks for every one in every scan, so
// that the example app can show each one it enables. A production backend asks only for those it uses.
const PERSONAL = ["local_addresses", "accessibility", "notification_access", "other_access",
  "screen_capture", "location", "mock_location"];

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

// --- Binary values travel as base64url without padding; hashes are hex SHA-256.

function b64urlDecode(text: unknown): Buffer {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error("not base64url text");
  }
  return Buffer.from(text, "base64url");
}

const b64urlEncode = (raw: Buffer): string => raw.toString("base64url");
const sha256Hex = (raw: Buffer | string): string => crypto.createHash("sha256").update(raw).digest("hex");
const hmac = (key: Buffer, data: Buffer | string): Buffer => crypto.createHmac("sha256", key).update(data).digest();
const now = (): number => Math.floor(Date.now() / 1000);
const iso = (seconds: number): string => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value as object).sort()
      .map((key) => [key, sorted((value as Record<string, unknown>)[key])]));
  }
  return value;
}

const canonical = (value: unknown): Buffer => Buffer.from(JSON.stringify(sorted(value)), "utf8");

const isInt = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);

const same = (a: Buffer, b: Buffer): boolean => a.length === b.length && crypto.timingSafeEqual(a, b);

/** An answer of {"error": {"code", "message", "details"}} (section 4). */
class Refusal extends Error {
  constructor(readonly status: number, readonly code: string, message: string,
    readonly details?: JsonObject) {
    super(message);
  }
}

// --- The contract's rules (RULES.md): what a report's measurements are worth before any business
// logic weighs them -- never a score. A report is judged over the measurements its challenge
// required: complete, partial (part of the app's code compared), incomplete (something not measured)
// or invalid (figures that cannot all be true).

type Quality = "complete" | "partial" | "incomplete" | "invalid";
const QUALITIES: Quality[] = ["complete", "partial", "incomplete", "invalid"]; // best to worst
// Where code is always mapped, so that a comparison there finds some (RULES.md 4): on an iPhone only
// the app's own, the rest being unreadable.
const REGIONS: Record<string, string[]> = { android: ["core", "ext", "app"], ios: ["app"] };
const IOS_COVERAGE = ["app_images_expected", "app_images_compared", "app_images_unreadable",
  "app_images_skipped", "app_expected_bytes", "app_compared_bytes", "app_unreadable_bytes",
  "app_skipped_bytes", "app_complete", "main_executable_compared"];

type Definitions = Record<string, { "x-complete-when-ok"?: string[]; "x-complete-when-checked"?: string[] }>;

const isObject = (value: unknown): value is JsonObject =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const absent = (value: unknown): boolean => value === undefined || value === null;

/** The contract's judgment of a report whose shape the schema accepted. Split APKs out of order
 * (RULES.md 6, the one rule a schema cannot state) are refused rather than read. */
function judge(report: JsonObject, required: string[], definitions: Definitions): Quality {
  const platform = report.platform as string;
  const results = report.probe_results as JsonObject;
  const identity = results.app_identity;
  const splits = isObject(identity) ? identity.split_apks : undefined;
  if (Array.isArray(splits)) {
    const names = splits.map((entry) => (entry as JsonObject).name as string);
    // Sorted by name, by code unit as the strings compare, none twice.
    if (names.some((name, at) => at > 0 && !(names[at - 1] < name))) {
      throw new Refusal(400, "report_not_accepted", "The report is not the contract's.", { check: "split_apks" });
    }
  }
  const found: Quality[] = ["complete"];
  for (const name of required) {
    const value = results[name];
    const definition = definitions[`${platform}.${name}`] ?? {};
    if (!isObject(value) || value.status !== "ok") {
      found.push("incomplete"); // failed or unsupported: not measured (2)
      continue;
    }
    // ok is a claim: a measurement is complete with every field it lists, and with nothing in
    // unread (2).
    const unread = value.unread;
    if ((definition["x-complete-when-ok"] ?? []).some((field) => absent(value[field]))
      || (isObject(unread) && Object.keys(unread).length > 0)) {
      found.push("incomplete");
    }
    // Failed reads, not clean values (7).
    if ((["runtime_maps", "exec_mappings"].includes(name) && value.maps_lines === 0)
      || (name === "instrumentation_threads" && value.thread_count === 0)) {
      found.push("incomplete");
    }
    if (name === "exec_mappings" && wxSizesWithoutMappings(value)) found.push("invalid");
    if (name === "code_integrity") found.push(codeComparison(platform, value, definition));
  }
  // Contradictions across measurements (7).
  const capture = results.screen_capture;
  const device = results.device;
  if (isObject(capture) && capture.status === "ok" && capture.recording_status === "unsupported"
    && (platform === "ios" || (isObject(device) && isInt(device.sdk_int) && device.sdk_int >= 35))) {
    found.push("invalid"); // recording unsupported where it is measured
  }
  const location = results.location;
  const mock = results.mock_location;
  if (isObject(location) && isObject(mock) && location.status === "ok" && mock.status === "ok"
    && isInt(location.fix_time) && isInt(mock.fix_time) && location.fix_time !== mock.fix_time) {
    found.push("invalid"); // two fixes presented as one (5)
  }
  return found.reduce((worst, quality) =>
    QUALITIES.indexOf(quality) > QUALITIES.indexOf(worst) ? quality : worst);
}

/** No writable-and-executable mapping, with the sizes of such mappings listed (RULES.md 7). */
function wxSizesWithoutMappings(maps: JsonObject): boolean {
  let classes = 0;
  for (const part of String(maps.wx_size_classes ?? "").split(",")) {
    if (!part.trim()) continue;
    const at = part.indexOf(":");
    const size = (at < 0 ? part : part.slice(0, at)).trim();
    const count = (at < 0 ? "" : part.slice(at + 1)).trim();
    if (!/^[0-9]+$/.test(size) || !/^[0-9]+$/.test(count)) {
      classes = 0; // not a list of sizes
      break;
    }
    classes += 1;
  }
  const extremes = Boolean(maps.wx_smallest_bytes) || Boolean(maps.wx_largest_bytes);
  return maps.wx_mappings === 0 && !maps.wx_bytes && (classes > 0 || extremes);
}

/** The comparison of code in memory with its files (RULES.md 4): invalid when its figures do not add
 * up; incomplete when it did not run, lacks a figure, or compared nothing where code always is;
 * partial when it compared part of the code. */
function codeComparison(platform: string, code: JsonObject, definition: Definitions[string]): Quality {
  if (!(platform === "android" ? androidCoverageAddsUp(code) : iosCoverageAddsUp(code))) return "invalid";
  if (code.checked !== true || (definition["x-complete-when-checked"] ?? []).some((field) => absent(code[field]))) {
    return "incomplete";
  }
  if (REGIONS[platform].some((region) => code[`${region}_compared_bytes`] === 0)) return "incomplete";
  if (platform === "ios") return code.app_complete === true ? "complete" : "partial";
  const short = REGIONS.android.some((region) =>
    (code[`${region}_compared_bytes`] as number) < (code[`${region}_expected_bytes`] as number));
  return short || ((code.protect_restore_failures as number | undefined) ?? 0) > 0 ? "partial" : "complete";
}

/** In each region the expected bytes are the compared, skipped and unreadable ones together, and
 * <region>_complete is true exactly when some code was expected and all of it was compared. */
function androidCoverageAddsUp(code: JsonObject): boolean {
  for (const region of REGIONS.android) {
    const expected = code[`${region}_expected_bytes`];
    if (absent(expected)) continue;
    const parts = ["compared", "skipped", "unreadable"].map((kind) => code[`${region}_${kind}_bytes`]);
    if (!parts.every(isInt) || (parts as number[]).reduce((a, b) => a + b, 0) !== expected) return false;
    const complete = code[`${region}_complete`];
    if (!absent(complete) && complete !== ((expected as number) > 0 && parts[0] === expected)) return false;
  }
  return true;
}

/** Images and bytes both add up -- expected = compared + unreadable + skipped -- and app_complete is
 * true exactly when every image was compared, the main executable among them; bytes are compared
 * exactly when images are, and each image not compared is named. A collector that reports only part
 * of it is judged by its fields instead. */
function iosCoverageAddsUp(code: JsonObject): boolean {
  if (IOS_COVERAGE.some((field) => absent(code[field]))) return true;
  const figures = IOS_COVERAGE.slice(0, 8).map((field) => code[field]);
  if (!figures.every(isInt)) return false;
  const [expected, compared, unreadable, skipped, expectedBytes, comparedBytes, unreadableBytes,
    skippedBytes] = figures as number[];
  const complete = expected > 0 && compared === expected;
  const main = code.main_executable_compared;
  const named = code.app_images_not_compared;
  const namedCount = isObject(named) ? Object.keys(named).length : 0;
  return !(
    expected !== compared + unreadable + skipped
    || expectedBytes !== comparedBytes + unreadableBytes + skippedBytes
    || code.app_complete !== complete
    || (complete && (unreadableBytes > 0 || skippedBytes > 0))
    || (unreadableBytes > 0 && unreadable === 0) || (skippedBytes > 0 && skipped === 0)
    || (comparedBytes > 0) !== (compared > 0)
    || (!absent(code.checked) && code.checked !== (compared > 0))
    || (main === true && compared === 0) || (complete && main !== true)
    || (!absent(named) && (namedCount > unreadable + skipped || (unreadable + skipped > 0 && namedCount === 0))));
}

// Your business logic decides (the guide, section 7), and this is where it goes. This sample decides
// on the contract's judgment alone and scores nothing: a complete report lets the action go on, and
// so -- by this sample's choice -- does a partial one, whose comparison found nothing in the code it
// could read; an incomplete one asks for a scan again, since a failed read is no proof of an attack;
// and a report whose figures contradict each other is held for review. Only a report allowed here
// approves a scan made for one action.
const NEXT: Record<Quality, string> = { complete: "allow", partial: "allow", incomplete: "scan_again", invalid: "review" };

/** What to do next, for this report: allow, scan_again or review. */
function decide(judgment: Quality, report: JsonObject): string {
  void report; // your own rules read the measurements here
  return NEXT[judgment];
}

// --- Section 1: the installation key.

function publicKey(jwk: unknown): crypto.KeyObject {
  const key = jwk as Record<string, unknown> | null;
  if (key === null || typeof key !== "object" || key.kty !== "EC" || key.crv !== "P-256") {
    throw new Error("only EC P-256 keys are accepted");
  }
  const x = b64urlDecode(key.x);
  const y = b64urlDecode(key.y);
  if (x.length !== 32 || y.length !== 32) throw new Error("P-256 coordinates are 32 bytes each");
  // Throws for a point that is not on the curve.
  return crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: b64urlEncode(x), y: b64urlEncode(y) }, format: "jwk",
  });
}

function thumbprint(jwk: JsonObject): string {
  return sha256Hex(canonical({
    crv: "P-256", kty: "EC", x: b64urlEncode(b64urlDecode(jwk.x)), y: b64urlEncode(b64urlDecode(jwk.y)),
  }));
}

/** Whether the signature verifies over these bytes, as they were signed. */
function verifies(jwk: JsonObject, payload: Buffer, signature: unknown): boolean {
  try {
    return crypto.verify("sha256", payload, publicKey(jwk), b64urlDecode(signature));
  } catch {
    return false;
  }
}

/** PBKDF2 over an HMAC of the subject and the value, keyed by a secret the
 * records never hold: a copy of the records checks nothing. */
async function slowVerifier(secret: Buffer, subject: string, value: string,
  salt: Buffer = crypto.randomBytes(16)): Promise<[Buffer, Buffer]> {
  const keyed = hmac(secret, `${subject}:${value}`);
  return [salt, await pbkdf2(keyed, salt, VERIFIER_ROUNDS, 32, "sha256")];
}

interface Installation {
  thumbprint: string;
  jwk: JsonObject;
  platform: string;
  hint: string | null;
  keySecurity: Json;
  // A re-enrolled key carries the account that re-enrolled it.
  stepUp: { jwk: JsonObject; factor: string; mode: string; windowSeconds: number; account?: string } | null;
}

interface Session { kind: "installation" | "account"; installationId: string; account?: string; expires: number }

interface Account {
  passwordSalt: Buffer; passwordVerifier: Buffer;
  pinSalt: Buffer | null; pinVerifier: Buffer | null;
  pinFailures: number; pinLocked: boolean; pinChecking: number;
  // Each PIN set is a new generation; a check settles against the one it compared.
  pinGeneration: number;
}

class Request {
  readonly path: string;
  readonly query: string;
  readonly bearer: string | null;

  constructor(readonly method: string, url: string, readonly headers: http.IncomingHttpHeaders,
    readonly body: Buffer) {
    const at = url.indexOf("?");
    this.path = at < 0 ? url : url.slice(0, at);
    this.query = at < 0 ? "" : url.slice(at + 1);
    const auth = headers.authorization ?? "";
    this.bearer = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  }

  header(name: string): string | undefined {
    const value = this.headers[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
  }
}

const operationValid = (operation: unknown): boolean => {
  const op = operation as Record<string, unknown> | null;
  return op !== null && typeof op === "object" && !Array.isArray(op)
    && Object.keys(op).sort().join(",") === "body_sha256,method,path,query"
    && ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(op.method as string)
    && typeof op.path === "string" && op.path.startsWith("/") && typeof op.query === "string"
    && typeof op.body_sha256 === "string" && /^[0-9a-f]{64}$/.test(op.body_sha256);
};

class Backend {
  // Secrets made at start: a restart forgets every session and challenge.
  private readonly challengeKey = crypto.randomBytes(32);
  private readonly hintKey = crypto.randomBytes(32);
  private readonly pinSecret = crypto.randomBytes(32);
  private readonly passwordSecret = crypto.randomBytes(32);
  private readonly pinProofKey = crypto.randomBytes(32);
  private readonly installations = new Map<string, Installation>();
  private readonly byThumbprint = new Map<string, string>();
  private readonly usedKeyChallenges = new Set<string>();
  private readonly sessions = new Map<string, Session>();
  private readonly nonces = new Map<string, number>();
  private readonly scanChallenges = new Map<string, {
    installationId: string; platform: string; nonceSha256: string; required: string[];
    expires: number; used: boolean; operationSha256: string | null; session: string | null;
  }>();
  private readonly reports = new Map<string, {
    installationId: string; at: number; used: boolean; operationSha256: string | null;
    session: string | null; judgment: Quality; next: string;
  }>();
  private readonly accounts = new Map<string, Account>();
  readonly pending = new Map<string, JsonObject>(); // test control: the next request's refusal
  // Test control: while set, PIN checks wait on it; released with fail, their verifier fails.
  private pinGate: { released: Promise<boolean>; release: (fail: boolean) => void } | null = null;
  private pinWaiting = 0; // test control: the PIN checks waiting now

  constructor(private readonly validate: ReturnType<Ajv2020["compile"]>,
    private readonly definitions: Definitions, // the contract's x- annotations
    readonly testToken: string | null) {} // test controls answer only this token

  // --- Section 1: registration.

  register(body: JsonObject): JsonObject {
    const installationId = body.installation_id;
    const platform = body.platform;
    let jwk: JsonObject;
    try {
      if (typeof installationId !== "string"
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(installationId)) {
        throw new Error("not a UUID");
      }
      publicKey(body.public_key);
      jwk = body.public_key as JsonObject;
    } catch {
      throw new Refusal(400, "bad_request", "A UUID and an EC P-256 public key are required.",
        { field: "public_key" });
    }
    if (platform !== "android" && platform !== "ios") {
      throw new Refusal(400, "bad_request", "The platform is android or ios.", { field: "platform" });
    }
    const hint = body.reinstall_hint as JsonObject | null | undefined;
    if (hint != null && !(typeof hint === "object" && ["android_id_sha256", "idfv_sha256"].includes(hint.kind as string)
      && typeof hint.value === "string" && /^[0-9a-f]{64}$/.test(hint.value))) {
      throw new Refusal(400, "bad_request", "The reinstall hint is malformed.", { field: "reinstall_hint" });
    }
    const key = thumbprint(jwk);
    const stepUp = this.stepUpKey(body, key);
    const held = this.byThumbprint.get(key);
    if (held !== undefined) {
      // The thumbprint is the identity: the same key is the same installation,
      // whatever ID it proposes. A step-up key offered now is not taken --
      // only re-enrolment replaces one -- so the answer says whether it is the
      // one held, and the app asks for re-enrolment rather than sign with a
      // key this backend lacks.
      const bound = (this.installations.get(held) as Installation).stepUp;
      return {
        installation_id: held, stepup_key_registered: bound !== null,
        stepup_key_matches: stepUp === null ? null
          : bound !== null && thumbprint(bound.jwk) === thumbprint(stepUp.jwk),
      };
    }
    if (this.installations.has(installationId)) {
      throw new Refusal(409, "installation_id_taken", "This installation ID belongs to another key.");
    }
    this.installations.set(installationId, {
      thumbprint: key, jwk, platform,
      // Keyed before it is kept: what the app says, never proof.
      hint: hint ? hmac(this.hintKey, hint.value as string).toString("hex") : null,
      // Recorded, never relied on: the phone cannot prove it.
      keySecurity: body.key_security ?? null,
      stepUp,
    });
    this.byThumbprint.set(key, installationId);
    return { installation_id: installationId, stepup_key_registered: stepUp !== null };
  }

  /** Section 3, step-up: the key and how the phone says it is unlocked. */
  private stepUpKey(body: JsonObject, installationThumbprint: string): Installation["stepUp"] {
    const jwk = body.stepup_public_key;
    if (jwk === undefined || jwk === null) return null;
    try {
      publicKey(jwk);
    } catch {
      throw new Refusal(400, "bad_request", "The step-up key is not an EC P-256 key.",
        { field: "stepup_public_key" });
    }
    if (thumbprint(jwk as JsonObject) === installationThumbprint) {
      throw new Refusal(400, "bad_request", "The step-up key must not be the installation key.",
        { field: "stepup_public_key" });
    }
    const auth = body.stepup_key_auth as JsonObject | null;
    const window = auth?.window_seconds;
    if (!(auth && typeof auth === "object" && ["passcode", "biometric"].includes(auth.factor as string)
      && isInt(window) && ((auth.mode === "per_use" && window === 0)
        || (auth.mode === "windowed" && window >= 1 && window <= 3600)))) {
      throw new Refusal(400, "bad_request", "stepup_key_auth is malformed.", { field: "stepup_key_auth" });
    }
    return { jwk: jwk as JsonObject, factor: auth.factor as string, mode: auth.mode as string, windowSeconds: window };
  }

  // --- Section 1: proof of possession, with a challenge that stores nothing.

  keyChallenge(body: JsonObject): JsonObject {
    const installationId = body.installation_id;
    if (typeof installationId !== "string" || !this.installations.has(installationId)) {
      throw new Refusal(404, "installation_not_found", "No such installation.");
    }
    const expires = now() + KEY_CHALLENGE_SECONDS;
    const claims: JsonObject = {
      challenge_id: crypto.randomUUID(), installation_id: installationId, purpose: "prove_installation",
      nonce: b64urlEncode(crypto.randomBytes(32)), expires_at: expires,
    };
    claims.mac = b64urlEncode(hmac(this.challengeKey, canonical(claims)));
    return { challenge_id: claims.challenge_id, payload: b64urlEncode(canonical(claims)), expires_at: iso(expires) };
  }

  verify(body: JsonObject): JsonObject {
    const installationId = body.installation_id;
    const challengeId = body.challenge_id;
    let payload: Buffer;
    let claims: JsonObject;
    let mac: Buffer;
    try {
      payload = b64urlDecode(body.payload);
      claims = JSON.parse(payload.toString("utf8"));
      mac = b64urlDecode(claims.mac);
      delete claims.mac;
    } catch {
      throw new Refusal(401, "proof_not_accepted", "This is not a challenge of ours.");
    }
    if (!same(mac, hmac(this.challengeKey, canonical(claims))) || claims.challenge_id !== challengeId
      || claims.installation_id !== installationId || claims.purpose !== "prove_installation") {
      throw new Refusal(401, "proof_not_accepted", "This is not a challenge of ours.");
    }
    if ((claims.expires_at as number) < now()) {
      throw new Refusal(401, "challenge_expired", "The challenge has expired.");
    }
    const installation = this.installations.get(installationId as string);
    if (installation === undefined) throw new Refusal(404, "installation_not_found", "No such installation.");
    if (!verifies(installation.jwk, payload, body.signature)) {
      throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
    }
    // Consumed only after the signature verifies; one event loop makes it atomic.
    if (this.usedKeyChallenges.has(challengeId as string)) {
      throw new Refusal(401, "challenge_used", "The challenge was answered already.");
    }
    this.usedKeyChallenges.add(challengeId as string);
    const token = crypto.randomBytes(32).toString("base64url");
    this.sessions.set(token, { kind: "installation", installationId: installationId as string, expires: now() + SESSION_SECONDS });
    return { device_token: token, expires_at: iso(now() + SESSION_SECONDS) };
  }

  // --- Section 3: every request carries a request proof.

  authenticate(request: Request, kinds: string[]): [Session, Installation, string] {
    const token = request.bearer;
    const session = token ? this.sessions.get(token) : undefined;
    if (session === undefined || !kinds.includes(session.kind)) {
      throw new Refusal(401, "not_signed_in", "This request needs a session of ours.");
    }
    if (session.expires < now()) throw new Refusal(401, "expired_token", "The session has expired.");
    const installation = this.installations.get(session.installationId);
    if (installation === undefined) throw new Refusal(404, "installation_not_found", "No such installation.");
    let raw: Buffer;
    let proof: JsonObject;
    let nonce: Buffer;
    try {
      raw = b64urlDecode(request.header("X-Access-Proof"));
      proof = JSON.parse(raw.toString("utf8"));
      nonce = b64urlDecode(proof.nonce);
    } catch {
      throw new Refusal(401, "proof_not_accepted", "The request proof is missing or malformed.");
    }
    const expected: JsonObject = {
      access_token_sha256: sha256Hex(token as string), body_sha256: sha256Hex(request.body),
      installation_id: session.installationId, method: request.method, path: request.path,
      query: request.query, version: 2,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (proof[field] !== value) {
        throw new Refusal(401, "proof_not_accepted", "The request proof is for another request.", { check: field });
      }
    }
    const timestamp = proof.timestamp;
    if (!isInt(timestamp) || Math.abs(now() - timestamp) > CLOCK_WINDOW_SECONDS || nonce.length !== 32) {
      throw new Refusal(401, "proof_not_accepted", "The request proof is out of time.", { check: "timestamp" });
    }
    if (!verifies(installation.jwk, raw, request.header("X-Access-Signature"))) {
      throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
    }
    // Stored only after the signature verifies, under a unique key.
    for (const [kept, until] of this.nonces) if (until < now()) this.nonces.delete(kept);
    const key = sha256Hex(nonce);
    if (this.nonces.has(key)) throw new Refusal(401, "proof_reused", "This request was sent already.");
    this.nonces.set(key, now() + NONCE_KEEP_SECONDS);
    return [session, installation, proof.nonce as string];
  }

  // --- Section 2: the scan.

  scanChallenge(request: Request, body: JsonObject): JsonObject {
    const [session, installation] = this.authenticate(request, ["installation", "account"]);
    const operation = body.operation;
    let digest: string | null = null;
    if (operation !== undefined && operation !== null) {
      // A scan for one action is the account's, never the installation's.
      if (session.kind !== "account" || !operationValid(operation)) {
        throw new Refusal(400, "invalid_operation",
          "An operation is named only under an account session, whole.");
      }
      digest = sha256Hex(canonical(operation));
    }
    const platform = installation.platform;
    // Each of the others on about half the scans, unpredictably.
    const required = [...RELIED_ON[platform], ...VARIED[platform].filter(() => crypto.randomInt(2) === 1)];
    const nonce = crypto.randomBytes(32);
    const challengeId = crypto.randomUUID();
    const expires = now() + SCAN_CHALLENGE_SECONDS;
    this.scanChallenges.set(challengeId, {
      installationId: session.installationId, platform, nonceSha256: sha256Hex(nonce), required,
      expires, used: false, operationSha256: digest, session: digest ? request.bearer : null,
    });
    return {
      challenge_id: challengeId, nonce: b64urlEncode(nonce), platform, required_probes: required,
      optional_probes: [...PERSONAL], expires_at: iso(expires),
    };
  }

  report(request: Request, body: JsonObject): JsonObject {
    const [session, installation] = this.authenticate(request, ["installation", "account"]);
    // 1. Decoded, at most the contract's size, a JSON object of version 1.
    let payload: Buffer;
    let report: JsonObject;
    try {
      payload = b64urlDecode(body.report_payload);
      if (payload.length > MAX_REPORT_BYTES) throw new Error("too large");
      report = JSON.parse(payload.toString("utf8"));
      if (report === null || typeof report !== "object" || Array.isArray(report) || report.version !== 1) {
        throw new Error("version");
      }
    } catch (error) {
      throw new Refusal(400, "report_not_accepted", "The report is not one we read.",
        { check: (error as Error).message });
    }
    // 2. Its installation is the session's.
    if (report.installation_id !== session.installationId) {
      throw new Refusal(400, "report_not_accepted", "The report names another installation.",
        { check: "installation_id" });
    }
    // 3. Its challenge: this installation's, for its platform.
    const challenge = this.scanChallenges.get(report.challenge_id as string);
    if (challenge === undefined || challenge.installationId !== session.installationId
      || report.platform !== challenge.platform) {
      throw new Refusal(400, "report_not_accepted", "The report answers no challenge of ours.",
        { check: "challenge_id" });
    }
    // 4. Unused and in time.
    if (challenge.used) throw new Refusal(401, "integrity_challenge_replay", "The challenge was answered already.");
    if (challenge.expires < now()) throw new Refusal(401, "integrity_challenge_expired", "The challenge has expired.");
    // 5. The nonce it was given.
    let nonce: Buffer = Buffer.alloc(0);
    try {
      nonce = b64urlDecode(report.challenge_nonce);
    } catch { /* an empty nonce, which matches nothing */ }
    if (!same(Buffer.from(sha256Hex(nonce)), Buffer.from(challenge.nonceSha256))) {
      throw new Refusal(400, "report_not_accepted", "The report carries another nonce.",
        { check: "challenge_nonce" });
    }
    // 6. The phone's clock.
    const collected = report.collected_at;
    if (!isInt(collected) || Math.abs(now() - collected) > REPORT_CLOCK_SECONDS) {
      throw new Refusal(400, "integrity_report_stale", "The phone's clock is far off.");
    }
    // 7. A collector this backend reads.
    const version = report.collector_version;
    if (!isInt(version) || version < MIN_COLLECTOR[challenge.platform]) {
      throw new Refusal(400, "report_not_accepted", "This collector is too old.", { check: "collector_version" });
    }
    // 8. Every measurement asked for.
    const results = report.probe_results;
    const missing = challenge.required.filter((probe) =>
      results === null || typeof results !== "object" || Array.isArray(results) || !(probe in results));
    if (missing.length > 0) {
      throw new Refusal(400, "integrity_probe_missing", "A measurement asked for is missing.",
        { missing_probes: missing });
    }
    // 9. The signature, over the decoded bytes.
    if (!verifies(installation.jwk, payload, body.report_signature)) {
      throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
    }
    // 10. Used; one event loop makes the checks and the marking one unit.
    challenge.used = true;
    // Only then are the measurements read: first, whether they are the contract's.
    this.checkShape(report);
    // Then what they are worth, by the contract's rules; then the decision.
    const judgment = judge(report, challenge.required, this.definitions);
    const decision = decide(judgment, report);
    const reportId = crypto.randomUUID();
    this.reports.set(reportId, {
      installationId: session.installationId, at: now(), used: false,
      operationSha256: challenge.operationSha256, session: challenge.session, judgment, next: decision,
    });
    // The answer says what to do next, never the judgment, a score or a reason (section 7).
    return { integrity: { report_id: reportId, next: decision } };
  }

  /** The report against the contract's schema: its shape. */
  checkShape(report: JsonObject): void {
    if (!this.validate(report)) {
      throw new Refusal(400, "report_not_accepted", "The report is not the contract's.",
        { check: "schema", at: this.validate.errors?.[0]?.instancePath ?? "" });
    }
  }

  // --- Section 2: a scan for one action, used by the request it named.

  requireOperationScan(request: Request): void {
    const stored = this.reports.get(request.header("X-Integrity-Report") ?? "");
    const here = sha256Hex(canonical({
      method: request.method, path: request.path, query: request.query, body_sha256: sha256Hex(request.body),
    }));
    // A scan made for this request, under this session, lately -- and one the decision allowed.
    if (stored === undefined || stored.used || stored.operationSha256 !== here
      || stored.session !== request.bearer || now() - stored.at > OPERATION_SCAN_SECONDS
      || stored.next !== "allow") {
      throw new Refusal(403, "needs_scan", "This request needs a scan made for it.");
    }
    stored.used = true;
  }

  // --- Section 3: step-up.

  requireStepUp(request: Request, session: Session, installation: Installation, nonce: string): void {
    const stepUp = installation.stepUp;
    const proofText = request.header("X-Step-Up-Proof");
    const signature = request.header("X-Step-Up-Signature");
    if (!proofText || !signature || stepUp === null) {
      throw new Refusal(403, "needs_step_up", "This request needs the person's approval.");
    }
    // A re-enrolled key approves for the account that re-enrolled it alone.
    if (stepUp.account !== undefined && stepUp.account !== session.account) {
      throw new Refusal(403, "step_up_not_accepted", "The step-up key is another account's.", { check: "account" });
    }
    let raw: Buffer = Buffer.alloc(0);
    let proof: JsonObject = {};
    try {
      raw = b64urlDecode(proofText);
      proof = JSON.parse(raw.toString("utf8"));
    } catch { /* fails the signature below */ }
    if (!verifies(stepUp.jwk, raw, signature)) {
      throw new Refusal(403, "step_up_not_accepted", "The approval does not verify.", { check: "signature" });
    }
    const expected: JsonObject = {
      version: 2, purpose: "stepup", installation_id: session.installationId,
      access_token_sha256: sha256Hex(request.bearer as string), method: request.method, path: request.path,
      query: request.query, body_sha256: sha256Hex(request.body), nonce,
      // The factor this sample requires is the one the key was made with.
      factor: stepUp.factor,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (proof[field] !== value) {
        throw new Refusal(403, "step_up_not_accepted", "The approval is for another request.", { check: field });
      }
    }
    if (!isInt(proof.timestamp) || Math.abs(now() - proof.timestamp) > CLOCK_WINDOW_SECONDS) {
      throw new Refusal(403, "step_up_not_accepted", "The approval is out of time.", { check: "timestamp" });
    }
  }

  // --- Section 3: re-enrolment, a new step-up key for this account alone.

  async reenrolStepUp(request: Request, body: JsonObject): Promise<JsonObject> {
    const [session, installation, nonce] = this.authenticate(request, ["account"]);
    const stepUp = this.stepUpKey(body, installation.thumbprint);
    if (stepUp === null) {
      throw new Refusal(400, "bad_request", "A new step-up key is required.", { field: "stepup_public_key" });
    }
    let raw: Buffer = Buffer.alloc(0);
    let proof: JsonObject = {};
    try {
      raw = b64urlDecode(body.stepup_key_proof as string);
      proof = JSON.parse(raw.toString("utf8"));
    } catch { /* fails the signature below */ }
    // Every check of the new key before the password, so that this call cannot serve to guess it.
    if (!verifies(stepUp.jwk, raw, body.stepup_key_signature)) {
      throw new Refusal(403, "step_up_not_accepted", "The new key's proof does not verify.", { check: "signature" });
    }
    const expected: JsonObject = {
      version: 1, purpose: "stepup_reenrol", installation_id: session.installationId,
      stepup_key_thumbprint: thumbprint(stepUp.jwk), nonce,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (proof === null || typeof proof !== "object" || proof[field] !== value) {
        throw new Refusal(403, "step_up_not_accepted", "The new key's proof is for another request.",
          { check: field });
      }
    }
    if (!isInt(proof.timestamp) || Math.abs(now() - proof.timestamp) > CLOCK_WINDOW_SECONDS) {
      throw new Refusal(403, "step_up_not_accepted", "The new key's proof is out of time.", { check: "timestamp" });
    }
    const account = this.accounts.get(session.account as string) as Account;
    await this.reauthenticate(account, session.account as string, body.password);
    // Another account on the phone, which needs only the installation key, gains no step-up from it.
    installation.stepUp = { ...stepUp, account: session.account as string };
    return { stepup_key_registered: true };
  }

  // --- Section 3: the app PIN.

  async setAppPin(request: Request, body: JsonObject): Promise<JsonObject> {
    const [session] = this.authenticate(request, ["account"]);
    const account = this.accounts.get(session.account as string) as Account;
    await this.reauthenticate(account, session.account as string, body.password);
    const pin = body.pin;
    if (!(typeof pin === "string" && pin.length === PIN_LENGTH && /^[0-9]+$/.test(pin))) {
      throw new Refusal(400, "bad_request", `The PIN is ${PIN_LENGTH} digits.`, { field: "pin" });
    }
    const [salt, verifier] = await slowVerifier(this.pinSecret, session.account as string, pin);
    // A new PIN clears the wrong ones and any lock, and is a new generation: checks of the PIN it
    // replaces settle against that one, and the proofs made under it no longer serve.
    Object.assign(account, {
      pinSalt: salt, pinVerifier: verifier, pinFailures: 0, pinLocked: false, pinChecking: 0,
      pinGeneration: account.pinGeneration + 1,
    });
    return { app_pin_set: true };
  }

  async proveAppPin(request: Request, body: JsonObject): Promise<JsonObject> {
    const [session] = this.authenticate(request, ["account"]);
    const pin = body.pin;
    const target = body.request as JsonObject | null;
    let complete = false;
    try {
      complete = typeof pin === "string" && pin.length > 0 && target !== null && typeof target === "object"
        && operationValid({ method: target.method, path: target.path, query: target.query, body_sha256: target.body_sha256 })
        && b64urlDecode(target.nonce).length === 32;
    } catch { /* incomplete */ }
    if (!complete) {
      // Refused before the PIN is checked.
      throw new Refusal(400, "bad_request", "Send the PIN and the request it unlocks.", { field: "request" });
    }
    const account = this.accounts.get(session.account as string) as Account;
    if (account.pinVerifier === null || account.pinSalt === null) {
      throw new Refusal(403, "app_pin_not_set", "No app PIN is set for this account.");
    }
    if (account.pinLocked) throw new Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.");
    if (account.pinFailures + account.pinChecking >= PIN_ATTEMPTS) {
      // The attempts left are held by checks still running.
      throw new Refusal(429, "pin_busy", "The PIN is being checked; try again in a moment.",
        { retry_after_seconds: 1 });
    }
    account.pinChecking += 1; // the attempt, claimed before comparing
    const generation = account.pinGeneration;
    const salt = account.pinSalt;
    const verifier = account.pinVerifier;
    let right: boolean | null;
    try {
      await this.heldPinCheck();
      right = same((await slowVerifier(this.pinSecret, session.account as string, pin as string, salt))[1], verifier);
    } catch {
      right = null; // the check could not run
    }
    // Settled in one step -- nothing awaited from here on -- against the PIN it compared: a PIN set
    // meanwhile is left alone -- its count, its lock, its checks -- and a check that could not run
    // gives its attempt back.
    const current = account.pinGeneration === generation;
    if (current) {
      account.pinChecking -= 1;
      if (right === true) {
        account.pinFailures = 0;
      } else if (right === false) {
        account.pinFailures += 1;
        account.pinLocked = account.pinFailures >= PIN_ATTEMPTS;
      }
    }
    if (right === null) throw new Refusal(503, "pin_unavailable", "The app PIN cannot be checked now; try again.");
    if (!current) {
      // Neither a proof nor a count: the PIN it was right or wrong for is no longer the account's.
      throw new Refusal(403, "app_pin_invalid", "The app PIN was changed while it was checked; enter it again.");
    }
    if (!right) {
      if (account.pinLocked) throw new Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.");
      throw new Refusal(403, "app_pin_invalid", "The app PIN is wrong.");
    }
    const expires = now() + PIN_PROOF_SECONDS;
    const claims = canonical({
      account: session.account as string, installation_id: session.installationId,
      session_sha256: sha256Hex(request.bearer as string), request: target, expires_at: expires,
      pin_generation: generation,
    });
    return {
      app_pin_proof: `${b64urlEncode(claims)}.${b64urlEncode(hmac(this.pinProofKey, claims))}`,
      expires_at: iso(expires),
    };
  }

  requireAppPin(request: Request, session: Session, nonce: string): void {
    let proof: JsonObject | null = null;
    try {
      const [encoded, mac] = (request.header("X-App-PIN-Proof") ?? "").split(".");
      const claims = b64urlDecode(encoded);
      if (same(b64urlDecode(mac), hmac(this.pinProofKey, claims))) proof = JSON.parse(claims.toString("utf8"));
    } catch { /* not a proof of ours */ }
    if (proof === null) throw new Refusal(403, "needs_app_pin", "This request needs the app PIN.");
    const generation = (this.accounts.get(session.account as string) as Account).pinGeneration;
    if (proof.pin_generation !== generation) {
      throw new Refusal(403, "app_pin_not_accepted", "The app PIN was changed since this proof was made; enter it again.");
    }
    const expected = canonical({
      account: session.account as string, installation_id: session.installationId,
      session_sha256: sha256Hex(request.bearer as string),
      request: {
        method: request.method, path: request.path, query: request.query,
        body_sha256: sha256Hex(request.body), nonce,
      },
      pin_generation: generation,
    });
    const { expires_at: expires, ...bound } = proof;
    if (!isInt(expires) || expires < now() || !canonical(bound).equals(expected)) {
      throw new Refusal(403, "app_pin_not_accepted", "The PIN's proof is for another request.");
    }
  }

  // --- This sample's own account API, in which the plugin's proofs are used.

  async signIn(request: Request, body: JsonObject): Promise<JsonObject> {
    const [session] = this.authenticate(request, ["installation"]);
    const handle = body.handle;
    const password = body.password;
    if (typeof handle !== "string" || !handle || typeof password !== "string" || !password) {
      throw new Refusal(400, "bad_request", "A handle and a password are required.");
    }
    let account = this.accounts.get(handle);
    if (account === undefined) {
      const [salt, verifier] = await slowVerifier(this.passwordSecret, handle, password);
      account = this.accounts.get(handle) ?? {
        passwordSalt: salt, passwordVerifier: verifier, pinSalt: null, pinVerifier: null,
        pinFailures: 0, pinLocked: false, pinChecking: 0, pinGeneration: 0,
      };
      this.accounts.set(handle, account);
    }
    await this.reauthenticate(account, handle, password);
    const token = crypto.randomBytes(32).toString("base64url");
    // An account session for this installation, which proved its key.
    this.sessions.set(token, {
      kind: "account", installationId: session.installationId, account: handle, expires: now() + SESSION_SECONDS,
    });
    return { account_session: token };
  }

  private async reauthenticate(account: Account, handle: string, password: unknown): Promise<void> {
    const [, verifier] = await slowVerifier(this.passwordSecret, handle, String(password), account.passwordSalt);
    if (!same(verifier, account.passwordVerifier)) {
      throw new Refusal(401, "reauthentication_failed", "The password is wrong.");
    }
  }

  demo(request: Request, needs: string[]): JsonObject {
    const [session, installation, nonce] = this.authenticate(request, ["account"]);
    if (needs.includes("scan")) this.requireOperationScan(request);
    if (needs.includes("approval")) {
      // The person's approval, as the request offers it: step-up, the app PIN, or both -- and each
      // one offered must hold.
      const stepUp = Boolean(request.header("X-Step-Up-Proof"));
      const appPin = Boolean(request.header("X-App-PIN-Proof"));
      if (!stepUp && !appPin) {
        throw new Refusal(403, "needs_approval",
          "This request needs the person's approval: step-up or the app PIN.");
      }
      if (stepUp) this.requireStepUp(request, session, installation, nonce);
      if (appPin) this.requireAppPin(request, session, nonce);
    }
    return { done: request.path };
  }

  // --- Test controls, on only with --test-controls.

  /** A PIN check waits here, its attempt claimed, while a test holds PIN checks; released with fail,
   * its verifier fails. */
  private async heldPinCheck(): Promise<void> {
    const gate = this.pinGate;
    if (gate === null) return;
    this.pinWaiting += 1;
    const fail = await gate.released;
    this.pinWaiting -= 1;
    if (fail) throw new Error("the verifier failed, for a test");
  }

  control(path: string, body: JsonObject): JsonObject {
    if (path === "/test/expire-sessions") {
      for (const session of this.sessions.values()) session.expires = now() - 1;
    } else if (path === "/test/forget") {
      const record = this.installations.get(body.installation_id as string);
      if (record !== undefined) {
        this.installations.delete(body.installation_id as string);
        this.byThumbprint.delete(record.thumbprint);
      }
    } else if (path === "/test/refuse-next") {
      this.pending.set(body.path as string, body);
    } else if (path === "/test/judge") {
      // The contract's judgment of a report under a plan of the test's own, as the report call would
      // make it.
      try {
        this.checkShape(body.report as JsonObject);
        return { judged: judge(body.report as JsonObject, body.required_probes as string[], this.definitions) };
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        return { judged: "refused" };
      }
    } else if (path === "/test/pin-checks") {
      // Hold PIN checks once they claim their attempt, or release those waiting; the answer counts
      // those waiting.
      if (body.hold === true && this.pinGate === null) {
        let release: (fail: boolean) => void = () => undefined;
        const released = new Promise<boolean>((resolve) => { release = resolve; });
        this.pinGate = { released, release };
      } else if (body.hold === false && this.pinGate !== null) {
        this.pinGate.release(body.fail === true);
        this.pinGate = null;
      }
      return { ok: true, waiting: this.pinWaiting };
    } else {
      throw new Refusal(404, "no_such_path", "No such control.");
    }
    return { ok: true };
  }
}

type Route = (backend: Backend, request: Request, body: JsonObject) => JsonObject | Promise<JsonObject>;

const ROUTES: Record<string, Route> = {
  "/v1/installations/register": (b, r, body) => b.register(body),
  "/v1/installations/challenge": (b, r, body) => b.keyChallenge(body),
  "/v1/installations/verify": (b, r, body) => b.verify(body),
  "/v1/integrity/challenge": (b, r, body) => b.scanChallenge(r, body),
  "/v1/integrity/report": (b, r, body) => b.report(r, body),
  "/v1/installations/stepup-key": (b, r, body) => b.reenrolStepUp(r, body),
  "/v1/account/app-pin": (b, r, body) => b.setAppPin(r, body),
  "/v1/account/app-pin/proof": (b, r, body) => b.proveAppPin(r, body),
  "/v1/demo/sign-in": (b, r, body) => b.signIn(r, body),
  "/v1/demo/echo": (b, r) => b.demo(r, []),
  "/v1/demo/transfer": (b, r) => b.demo(r, ["scan"]),
  "/v1/demo/sensitive": (b, r) => b.demo(r, ["approval"]),
};

function answer(response: http.ServerResponse, status: number, value: unknown, request?: Request): void {
  // One line per call: the method, the path, the status and any refusal's code;
  // never a body or a header -- they hold PINs.
  const error = (value as { error?: { code?: string } } | null)?.error;
  console.log(`${request?.method ?? "-"} ${request?.path ?? "-"} ${status} ${error?.code ?? ""}`);
  const data = Buffer.from(JSON.stringify(value), "utf8");
  response.writeHead(status, { "Content-Type": "application/json", "Content-Length": data.length });
  response.end(data);
}

async function handle(backend: Backend, request: Request): Promise<[number, unknown]> {
  if (request.method === "GET") {
    return request.path === "/health" ? [200, { ok: true }]
      : [404, { error: { code: "no_such_path", message: "No such path." } }];
  }
  try {
    let body: JsonObject;
    try {
      body = request.body.length ? JSON.parse(request.body.toString("utf8")) : {};
    } catch {
      throw new Refusal(400, "bad_request", "The body is not JSON.");
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      throw new Refusal(400, "bad_request", "The body is not a JSON object.");
    }
    const token = Buffer.from(request.header("X-Test-Token") ?? "");
    if (request.path.startsWith("/test/") && backend.testToken !== null
      && same(token, Buffer.from(backend.testToken))) {
      return [200, backend.control(request.path, body)];
    }
    const pending = backend.pending.get(request.path);
    if (pending !== undefined) {
      backend.pending.delete(request.path);
      throw new Refusal((pending.status as number) ?? 400, pending.code as string, "Refused for a test.",
        (pending.details as JsonObject) ?? undefined);
    }
    const route = ROUTES[request.path];
    if (route === undefined) throw new Refusal(404, "no_such_path", "No such path.");
    return [200, await route(backend, request, body)];
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return [error.status, {
      error: { code: error.code, message: error.message, ...(error.details ? { details: error.details } : {}) },
    }];
  }
}

function main(): void {
  const args = process.argv.slice(2);
  const option = (name: string): string | undefined => {
    const at = args.indexOf(name);
    return at >= 0 ? args[at + 1] : undefined;
  };
  const schemaPath = option("--schema");
  if (!schemaPath) {
    console.error("usage: node dist/server.js --schema <contract>/report.schema.json [--port 8787] [--test-controls]");
    process.exit(2);
  }
  const port = Number(option("--port") ?? 8787);
  // Test controls answer only requests carrying X-Test-Token: $SAMPLE_TEST_TOKEN.
  const testToken = args.includes("--test-controls") ? process.env.SAMPLE_TEST_TOKEN ?? "" : null;
  if (testToken !== null && testToken.length < 16) {
    console.error("--test-controls needs SAMPLE_TEST_TOKEN, 16 characters or more");
    process.exit(2);
  }
  // The contract's own keywords (x-*) annotate; they constrain nothing.
  const ajv = new Ajv2020({ strict: false });
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  const backend = new Backend(ajv.compile(schema), schema.$defs ?? {}, testToken);
  const server = http.createServer((incoming, response) => {
    const chunks: Buffer[] = [];
    let size = 0;
    incoming.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= 1 << 20) chunks.push(chunk);
    });
    incoming.on("end", () => {
      if (size > 1 << 20) {
        answer(response, 413, { error: { code: "too_large", message: "Too large." } });
        return;
      }
      const request = new Request(incoming.method ?? "GET", incoming.url ?? "/", incoming.headers, Buffer.concat(chunks));
      handle(backend, request).then(([status, value]) => answer(response, status, value, request), () =>
        answer(response, 500, { error: { code: "server_error", message: "The sample failed." } }, request));
    });
  });
  // Logs one line per call, never a body or a header: they hold PINs.
  server.listen(port, "127.0.0.1", () => console.log(`listening on http://127.0.0.1:${port}`));
}

main();
