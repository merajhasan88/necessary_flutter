// A sample backend for the necessary plugin, written from the integration
// guide (doc/integration_guide.md) and the measurement contract alone.
//
// Sample code: one process, everything in memory, its secrets made at start.
// A real backend keeps its records in a database and its secrets in a vault.
// The section numbers below are the guide's. Run:
//
//     dotnet bin/Release/net10.0/SampleBackend.dll --port 8787 --schema <contract>/report.schema.json
//
// ASP.NET Core's minimal API and .NET's own cryptography, and JsonSchema.Net
// for the contract's schema.
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Json.Schema;
using Microsoft.AspNetCore.Http.Features;

namespace Necessary.SampleBackend;

/// <summary>An answer of {"error": {"code", "message", "details"}} (section 4).</summary>
public sealed class Refusal(int status, string code, string message, JsonObject? details = null)
    : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public JsonObject? Details { get; } = details;
}

public static class Wire
{
    // Binary values travel as base64url without padding; hashes are hex SHA-256.
    private static readonly Regex Base64Url = new("^[A-Za-z0-9_-]*$", RegexOptions.Compiled);

    public static byte[] Decode(string? text)
    {
        if (text is null || !Base64Url.IsMatch(text))
        {
            throw new FormatException("not base64url text");
        }
        return System.Buffers.Text.Base64Url.DecodeFromChars(text);
    }

    public static string Encode(byte[] raw) => System.Buffers.Text.Base64Url.EncodeToString(raw);

    public static string Sha256Hex(byte[] raw) => Convert.ToHexStringLower(SHA256.HashData(raw));

    public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text));

    public static byte[] Hmac(byte[] key, byte[] data) => HMACSHA256.HashData(key, data);

    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    public static string Iso(long seconds) =>
        DateTimeOffset.FromUnixTimeSeconds(seconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

    /// <summary>JSON with its members sorted, compact: the same bytes for the same value.</summary>
    public static byte[] Canonical(JsonNode? value) => Encoding.UTF8.GetBytes(Sorted(value)?.ToJsonString() ?? "null");

    private static JsonNode? Sorted(JsonNode? value) => value switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => KeyValuePair.Create(p.Key, Sorted(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Sorted).ToArray()),
        null => null,
        _ => value.DeepClone(),
    };

    public static bool Same(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    public static string? Text(JsonNode? node) =>
        node is JsonValue v && v.TryGetValue(out string? s) ? s : null;

    public static long? Integer(JsonNode? node) =>
        node is JsonValue v && v.GetValueKind() == JsonValueKind.Number && v.TryGetValue(out long n) ? n : null;
}

public sealed record StepUpKey(JsonObject Jwk, string Factor, string Mode, long WindowSeconds);

public sealed record Installation(string Thumbprint, JsonObject Jwk, string Platform, string? Hint,
    JsonNode? KeySecurity, StepUpKey? StepUp);

public sealed class Session
{
    public required string Kind { get; init; }
    public required string InstallationId { get; init; }
    public string? Account { get; init; }
    public long Expires { get; set; }
}

public sealed class Account
{
    public required byte[] PasswordSalt { get; init; }
    public required byte[] PasswordVerifier { get; init; }
    public byte[]? PinSalt { get; set; }
    public byte[]? PinVerifier { get; set; }
    public int PinFailures { get; set; }
    public bool PinLocked { get; set; }
    public int PinChecking { get; set; }
}

public sealed class ScanChallenge
{
    public required string InstallationId { get; init; }
    public required string Platform { get; init; }
    public required string NonceSha256 { get; init; }
    public required string[] Required { get; init; }
    public required long Expires { get; init; }
    public string? OperationSha256 { get; init; }
    public string? Session { get; init; }
    public bool Used { get; set; }
}

public sealed class StoredReport
{
    public required string InstallationId { get; init; }
    public required long At { get; init; }
    public string? OperationSha256 { get; init; }
    public string? Session { get; init; }
    public bool Used { get; set; }
}

public sealed class Call(string method, string path, string query, IHeaderDictionary headers, byte[] body)
{
    public string Method { get; } = method;
    public string Path { get; } = path;
    public string Query { get; } = query;
    public byte[] Body { get; } = body;
    public string? Bearer { get; } =
        headers.Authorization.ToString() is var auth && auth.StartsWith("Bearer ", StringComparison.Ordinal)
            ? auth[7..] : null;

    public string? Header(string name) => headers.TryGetValue(name, out var value) ? value.ToString() : null;
}

public sealed class Backend(JsonSchema schema, string? testToken)
{
    private const long SessionSeconds = 600;        // sessions: ten minutes (section 1)
    private const long KeyChallengeSeconds = 120;   // key challenges: two minutes (section 1)
    private const long ScanChallengeSeconds = 60;   // scan challenges: 60 seconds (section 2)
    private const long ClockWindowSeconds = 120;    // request and step-up proofs (section 3)
    private const long ReportClockSeconds = 90;     // a report's collected_at (section 2)
    private const long NonceKeepSeconds = 600;      // request-proof nonces, longer than the window
    private const long OperationScanSeconds = 120;  // a scan approves its request for a couple of minutes
    private const long PinProofSeconds = 120;       // an app PIN proof: about two minutes
    private const int PinLength = 6;                // this sample's choice of PIN length
    private const int PinAttempts = 5;              // this sample's limit of wrong PINs
    private const int MaxReportBytes = 65536;       // the contract's limit
    private const int VerifierRounds = 600_000;     // PBKDF2-HMAC-SHA256, a slow verifier

    private static readonly Dictionary<string, int> MinCollector = new() { ["android"] = 8, ["ios"] = 5 };

    // What this sample asks for in every scan, and the measurements it varies.
    private static readonly Dictionary<string, string[]> ReliedOn = new()
    {
        ["android"] = ["app_identity", "debug_state", "root_files", "runtime_maps", "tracer"],
        ["ios"] = ["app_identity", "code_signing", "debugger", "jailbreak_files", "sandbox", "dyld_images"],
    };

    private static readonly Dictionary<string, string[]> Varied = new()
    {
        ["android"] = ["system_properties", "root_shell", "selinux", "mounts", "frida_ports", "emulator",
            "developer_settings", "instrumentation_threads", "exec_mappings", "code_integrity"],
        ["ios"] = ["environment", "simulator"],
    };

    // The personal measurements (the guide, section 8): this sample asks for every one in every scan,
    // so that the example app can show each one it enables. A production backend asks only for those
    // it uses.
    private static readonly string[] Personal =
        ["local_addresses", "accessibility", "notification_access", "other_access", "screen_capture",
            "location", "mock_location"];

    private static readonly Regex Uuid =
        new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase);

    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$");

    // Secrets made at start: a restart forgets every session and challenge.
    private readonly byte[] _challengeKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _hintKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _pinSecret = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _passwordSecret = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _pinProofKey = RandomNumberGenerator.GetBytes(32);
    private readonly Lock _lock = new();
    private readonly Dictionary<string, Installation> _installations = new();
    private readonly Dictionary<string, string> _byThumbprint = new();
    private readonly HashSet<string> _usedKeyChallenges = new();
    private readonly Dictionary<string, Session> _sessions = new();
    private readonly Dictionary<string, long> _nonces = new();
    private readonly Dictionary<string, ScanChallenge> _scanChallenges = new();
    private readonly Dictionary<string, StoredReport> _reports = new();
    private readonly Dictionary<string, Account> _accounts = new();
    private readonly Dictionary<string, JsonObject> _pending = new();   // test control

    /// <summary>Test controls answer only requests carrying this token.</summary>
    public bool TestTokenMatches(string? given) =>
        testToken is not null && given is not null
        && Wire.Same(Encoding.UTF8.GetBytes(given), Encoding.UTF8.GetBytes(testToken));

    // --- Section 1: the installation key.

    private static ECDsa PublicKey(JsonNode? jwk)
    {
        if (jwk is not JsonObject key || Wire.Text(key["kty"]) != "EC" || Wire.Text(key["crv"]) != "P-256")
        {
            throw new FormatException("only EC P-256 keys are accepted");
        }
        var x = Wire.Decode(Wire.Text(key["x"]));
        var y = Wire.Decode(Wire.Text(key["y"]));
        if (x.Length != 32 || y.Length != 32)
        {
            throw new FormatException("P-256 coordinates are 32 bytes each");
        }
        // Throws for a point that is not on the curve.
        return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
    }

    private static string Thumbprint(JsonObject jwk) => Wire.Sha256Hex(Wire.Canonical(new JsonObject
    {
        ["crv"] = "P-256", ["kty"] = "EC",
        ["x"] = Wire.Encode(Wire.Decode(Wire.Text(jwk["x"]))), ["y"] = Wire.Encode(Wire.Decode(Wire.Text(jwk["y"]))),
    }));

    /// <summary>Whether the signature verifies over these bytes, as they were signed.</summary>
    private static bool Verifies(JsonObject jwk, byte[] payload, string? signature)
    {
        try
        {
            using var key = PublicKey(jwk);
            return key.VerifyData(payload, Wire.Decode(signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            return false;
        }
    }

    /// <summary>PBKDF2 over an HMAC of the subject and the value, keyed by a secret the
    /// records never hold: a copy of the records checks nothing.</summary>
    private static (byte[] Salt, byte[] Verifier) SlowVerifier(byte[] secret, string subject, string value,
        byte[]? salt = null)
    {
        salt ??= RandomNumberGenerator.GetBytes(16);
        var keyed = Wire.Hmac(secret, Encoding.UTF8.GetBytes($"{subject}:{value}"));
        return (salt, Rfc2898DeriveBytes.Pbkdf2(keyed, salt, VerifierRounds, HashAlgorithmName.SHA256, 32));
    }

    private static Task<(byte[] Salt, byte[] Verifier)> SlowVerifierAsync(byte[] secret, string subject,
        string value, byte[]? salt = null) => Task.Run(() => SlowVerifier(secret, subject, value, salt));

    // --- Section 1: registration.

    public JsonObject Register(JsonObject body)
    {
        var installationId = Wire.Text(body["installation_id"]);
        var platform = Wire.Text(body["platform"]);
        JsonObject jwk;
        try
        {
            if (installationId is null || !Uuid.IsMatch(installationId))
            {
                throw new FormatException("not a UUID");
            }
            PublicKey(body["public_key"]).Dispose();
            jwk = (JsonObject)body["public_key"]!;
        }
        catch (Exception e) when (e is FormatException or CryptographicException or InvalidCastException)
        {
            throw new Refusal(400, "bad_request", "A UUID and an EC P-256 public key are required.",
                new JsonObject { ["field"] = "public_key" });
        }
        if (platform is not ("android" or "ios"))
        {
            throw new Refusal(400, "bad_request", "The platform is android or ios.", new JsonObject { ["field"] = "platform" });
        }
        var hint = body["reinstall_hint"];
        if (hint is not null && !(hint is JsonObject h && Wire.Text(h["kind"]) is "android_id_sha256" or "idfv_sha256"
                                  && Wire.Text(hint["value"]) is { } value && Hex64.IsMatch(value)))
        {
            throw new Refusal(400, "bad_request", "The reinstall hint is malformed.", new JsonObject { ["field"] = "reinstall_hint" });
        }
        var key = Thumbprint(jwk);
        var stepUp = StepUpKeyOf(body, key);
        lock (_lock)
        {
            if (_byThumbprint.TryGetValue(key, out var held))
            {
                // The thumbprint is the identity: the same key is the same installation,
                // whatever ID it proposes. A step-up key offered now is not taken -- only
                // re-enrolment replaces one.
                return new JsonObject { ["installation_id"] = held };
            }
            if (_installations.ContainsKey(installationId))
            {
                throw new Refusal(409, "installation_id_taken", "This installation ID belongs to another key.");
            }
            _installations[installationId] = new Installation(key, (JsonObject)jwk.DeepClone(), platform,
                // Keyed before it is kept: what the app says, never proof.
                hint is null ? null : Convert.ToHexStringLower(Wire.Hmac(_hintKey, Encoding.ASCII.GetBytes(Wire.Text(hint["value"])!))),
                // Recorded, never relied on: the phone cannot prove it.
                body["key_security"]?.DeepClone(), stepUp);
            _byThumbprint[key] = installationId;
        }
        return new JsonObject { ["installation_id"] = installationId };
    }

    /// <summary>Section 3, step-up: the key and how the phone says it is unlocked.</summary>
    private static StepUpKey? StepUpKeyOf(JsonObject body, string installationThumbprint)
    {
        if (body["stepup_public_key"] is not { } node)
        {
            return null;
        }
        try
        {
            PublicKey(node).Dispose();
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            throw new Refusal(400, "bad_request", "The step-up key is not an EC P-256 key.",
                new JsonObject { ["field"] = "stepup_public_key" });
        }
        var jwk = (JsonObject)node;
        if (Thumbprint(jwk) == installationThumbprint)
        {
            throw new Refusal(400, "bad_request", "The step-up key must not be the installation key.",
                new JsonObject { ["field"] = "stepup_public_key" });
        }
        var auth = body["stepup_key_auth"] as JsonObject;
        var factor = Wire.Text(auth?["factor"]);
        var mode = Wire.Text(auth?["mode"]);
        var window = Wire.Integer(auth?["window_seconds"]);
        if (factor is not ("passcode" or "biometric") || window is null
            || !((mode == "per_use" && window == 0) || (mode == "windowed" && window is >= 1 and <= 3600)))
        {
            throw new Refusal(400, "bad_request", "stepup_key_auth is malformed.", new JsonObject { ["field"] = "stepup_key_auth" });
        }
        return new StepUpKey((JsonObject)jwk.DeepClone(), factor, mode!, window.Value);
    }

    // --- Section 1: proof of possession, with a challenge that stores nothing.

    public JsonObject KeyChallenge(JsonObject body)
    {
        var installationId = Wire.Text(body["installation_id"]);
        lock (_lock)
        {
            if (installationId is null || !_installations.ContainsKey(installationId))
            {
                throw new Refusal(404, "installation_not_found", "No such installation.");
            }
        }
        var expires = Wire.Now() + KeyChallengeSeconds;
        var claims = new JsonObject
        {
            ["challenge_id"] = Guid.NewGuid().ToString(), ["installation_id"] = installationId,
            ["purpose"] = "prove_installation", ["nonce"] = Wire.Encode(RandomNumberGenerator.GetBytes(32)),
            ["expires_at"] = expires,
        };
        claims["mac"] = Wire.Encode(Wire.Hmac(_challengeKey, Wire.Canonical(claims)));
        return new JsonObject
        {
            ["challenge_id"] = Wire.Text(claims["challenge_id"]), ["payload"] = Wire.Encode(Wire.Canonical(claims)),
            ["expires_at"] = Wire.Iso(expires),
        };
    }

    public JsonObject Verify(JsonObject body)
    {
        var installationId = Wire.Text(body["installation_id"]);
        var challengeId = Wire.Text(body["challenge_id"]);
        byte[] payload;
        JsonObject claims;
        byte[] mac;
        try
        {
            payload = Wire.Decode(Wire.Text(body["payload"]));
            claims = JsonNode.Parse(payload) as JsonObject ?? throw new FormatException("not an object");
            mac = Wire.Decode(Wire.Text(claims["mac"]));
            claims.Remove("mac");
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new Refusal(401, "proof_not_accepted", "This is not a challenge of ours.");
        }
        if (!Wire.Same(mac, Wire.Hmac(_challengeKey, Wire.Canonical(claims)))
            || Wire.Text(claims["challenge_id"]) != challengeId || Wire.Text(claims["installation_id"]) != installationId
            || Wire.Text(claims["purpose"]) != "prove_installation")
        {
            throw new Refusal(401, "proof_not_accepted", "This is not a challenge of ours.");
        }
        if (Wire.Integer(claims["expires_at"]) < Wire.Now())
        {
            throw new Refusal(401, "challenge_expired", "The challenge has expired.");
        }
        Installation? installation;
        lock (_lock)
        {
            _installations.TryGetValue(installationId!, out installation);
        }
        if (installation is null)
        {
            throw new Refusal(404, "installation_not_found", "No such installation.");
        }
        if (!Verifies(installation.Jwk, payload, Wire.Text(body["signature"])))
        {
            throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
        }
        var token = Wire.Encode(RandomNumberGenerator.GetBytes(32));
        lock (_lock)
        {
            // Consumed only after the signature verifies, atomically.
            if (!_usedKeyChallenges.Add(challengeId!))
            {
                throw new Refusal(401, "challenge_used", "The challenge was answered already.");
            }
            _sessions[token] = new Session { Kind = "installation", InstallationId = installationId!, Expires = Wire.Now() + SessionSeconds };
        }
        return new JsonObject { ["device_token"] = token, ["expires_at"] = Wire.Iso(Wire.Now() + SessionSeconds) };
    }

    // --- Section 3: every request carries a request proof.

    public (Session Session, Installation Installation, string Nonce) Authenticate(Call call, params string[] kinds)
    {
        Session? session;
        Installation? installation = null;
        lock (_lock)
        {
            _sessions.TryGetValue(call.Bearer ?? "", out session);
            if (session is not null)
            {
                _installations.TryGetValue(session.InstallationId, out installation);
            }
        }
        if (session is null || !kinds.Contains(session.Kind))
        {
            throw new Refusal(401, "not_signed_in", "This request needs a session of ours.");
        }
        if (session.Expires < Wire.Now())
        {
            throw new Refusal(401, "expired_token", "The session has expired.");
        }
        if (installation is null)
        {
            throw new Refusal(404, "installation_not_found", "No such installation.");
        }
        byte[] raw;
        JsonObject proof;
        byte[] nonce;
        try
        {
            raw = Wire.Decode(call.Header("X-Access-Proof"));
            proof = JsonNode.Parse(raw) as JsonObject ?? throw new FormatException("not an object");
            nonce = Wire.Decode(Wire.Text(proof["nonce"]));
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new Refusal(401, "proof_not_accepted", "The request proof is missing or malformed.");
        }
        var expected = new (string Field, JsonNode Value)[]
        {
            ("access_token_sha256", Wire.Sha256Hex(call.Bearer!)), ("body_sha256", Wire.Sha256Hex(call.Body)),
            ("installation_id", session.InstallationId), ("method", call.Method), ("path", call.Path),
            ("query", call.Query), ("version", 2),
        };
        foreach (var (field, value) in expected)
        {
            if (!JsonNode.DeepEquals(proof[field], value))
            {
                throw new Refusal(401, "proof_not_accepted", "The request proof is for another request.",
                    new JsonObject { ["check"] = field });
            }
        }
        var timestamp = Wire.Integer(proof["timestamp"]);
        if (timestamp is null || Math.Abs(Wire.Now() - timestamp.Value) > ClockWindowSeconds || nonce.Length != 32)
        {
            throw new Refusal(401, "proof_not_accepted", "The request proof is out of time.",
                new JsonObject { ["check"] = "timestamp" });
        }
        if (!Verifies(installation.Jwk, raw, call.Header("X-Access-Signature")))
        {
            throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
        }
        var key = Wire.Sha256Hex(nonce);
        lock (_lock)
        {
            // Stored only after the signature verifies, under a unique key.
            foreach (var kept in _nonces.Where(n => n.Value < Wire.Now()).Select(n => n.Key).ToList())
            {
                _nonces.Remove(kept);
            }
            if (!_nonces.TryAdd(key, Wire.Now() + NonceKeepSeconds))
            {
                throw new Refusal(401, "proof_reused", "This request was sent already.");
            }
        }
        return (session, installation, Wire.Text(proof["nonce"])!);
    }

    // --- Section 2: the scan.

    private static bool OperationValid(JsonNode? operation) =>
        operation is JsonObject op
        && op.Select(p => p.Key).Order(StringComparer.Ordinal).SequenceEqual(["body_sha256", "method", "path", "query"])
        && Wire.Text(op["method"]) is "GET" or "POST" or "PUT" or "PATCH" or "DELETE"
        && Wire.Text(op["path"]) is { } path && path.StartsWith('/')
        && Wire.Text(op["query"]) is not null
        && Wire.Text(op["body_sha256"]) is { } digest && Hex64.IsMatch(digest);

    public JsonObject ScanChallengeFor(Call call, JsonObject body)
    {
        var (session, installation, _) = Authenticate(call, "installation", "account");
        var operation = body["operation"];
        string? digest = null;
        if (operation is not null)
        {
            // A scan for one action is the account's, never the installation's.
            if (session.Kind != "account" || !OperationValid(operation))
            {
                throw new Refusal(400, "invalid_operation", "An operation is named only under an account session, whole.");
            }
            digest = Wire.Sha256Hex(Wire.Canonical(operation));
        }
        var platform = installation.Platform;
        // Varied from scan to scan, unpredictably, so a tampered app cannot prepare its answers.
        var varied = Varied[platform].ToArray();
        RandomNumberGenerator.Shuffle<string>(varied);
        var required = ReliedOn[platform].Concat(varied.Take(3)).ToArray();
        var nonce = RandomNumberGenerator.GetBytes(32);
        var challengeId = Guid.NewGuid().ToString();
        var expires = Wire.Now() + ScanChallengeSeconds;
        lock (_lock)
        {
            _scanChallenges[challengeId] = new ScanChallenge
            {
                InstallationId = session.InstallationId, Platform = platform, NonceSha256 = Wire.Sha256Hex(nonce),
                Required = required, Expires = expires, OperationSha256 = digest,
                Session = digest is null ? null : call.Bearer,
            };
        }
        return new JsonObject
        {
            ["challenge_id"] = challengeId, ["nonce"] = Wire.Encode(nonce), ["platform"] = platform,
            ["required_probes"] = new JsonArray(required.Select(p => (JsonNode)p).ToArray()),
            ["optional_probes"] = new JsonArray(Personal.Select(p => (JsonNode)p).ToArray()),
            ["expires_at"] = Wire.Iso(expires),
        };
    }

    public JsonObject Report(Call call, JsonObject body)
    {
        var (session, installation, _) = Authenticate(call, "installation", "account");
        // 1. Decoded, at most the contract's size, a JSON object of version 1.
        byte[] payload;
        JsonObject report;
        try
        {
            payload = Wire.Decode(Wire.Text(body["report_payload"]));
            if (payload.Length > MaxReportBytes)
            {
                throw new FormatException("too large");
            }
            report = JsonNode.Parse(payload) as JsonObject ?? throw new FormatException("version");
            if (Wire.Integer(report["version"]) != 1)
            {
                throw new FormatException("version");
            }
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new Refusal(400, "report_not_accepted", "The report is not one we read.",
                new JsonObject { ["check"] = e is JsonException ? "json" : e.Message });
        }
        // 2. Its installation is the session's.
        if (Wire.Text(report["installation_id"]) != session.InstallationId)
        {
            throw new Refusal(400, "report_not_accepted", "The report names another installation.",
                new JsonObject { ["check"] = "installation_id" });
        }
        ScanChallenge? challenge;
        lock (_lock)
        {
            // 3. Its challenge, held while it is checked: this installation's, for its platform.
            _scanChallenges.TryGetValue(Wire.Text(report["challenge_id"]) ?? "", out challenge);
            if (challenge is null || challenge.InstallationId != session.InstallationId
                || Wire.Text(report["platform"]) != challenge.Platform)
            {
                throw new Refusal(400, "report_not_accepted", "The report answers no challenge of ours.",
                    new JsonObject { ["check"] = "challenge_id" });
            }
            // 4. Unused and in time.
            if (challenge.Used)
            {
                throw new Refusal(401, "integrity_challenge_replay", "The challenge was answered already.");
            }
            if (challenge.Expires < Wire.Now())
            {
                throw new Refusal(401, "integrity_challenge_expired", "The challenge has expired.");
            }
            // 5. The nonce it was given.
            byte[] nonce;
            try
            {
                nonce = Wire.Decode(Wire.Text(report["challenge_nonce"]));
            }
            catch (FormatException)
            {
                nonce = [];
            }
            if (!Wire.Same(Encoding.ASCII.GetBytes(Wire.Sha256Hex(nonce)), Encoding.ASCII.GetBytes(challenge.NonceSha256)))
            {
                throw new Refusal(400, "report_not_accepted", "The report carries another nonce.",
                    new JsonObject { ["check"] = "challenge_nonce" });
            }
            // 6. The phone's clock.
            var collected = Wire.Integer(report["collected_at"]);
            if (collected is null || Math.Abs(Wire.Now() - collected.Value) > ReportClockSeconds)
            {
                throw new Refusal(400, "integrity_report_stale", "The phone's clock is far off.");
            }
            // 7. A collector this backend reads.
            var version = Wire.Integer(report["collector_version"]);
            if (version is null || version < MinCollector[challenge.Platform])
            {
                throw new Refusal(400, "report_not_accepted", "This collector is too old.",
                    new JsonObject { ["check"] = "collector_version" });
            }
            // 8. Every measurement asked for.
            var results = report["probe_results"] as JsonObject;
            var missing = challenge.Required.Where(p => results is null || !results.ContainsKey(p)).ToArray();
            if (missing.Length > 0)
            {
                throw new Refusal(400, "integrity_probe_missing", "A measurement asked for is missing.",
                    new JsonObject { ["missing_probes"] = new JsonArray(missing.Select(p => (JsonNode)p).ToArray()) });
            }
            // 9. The signature, over the decoded bytes.
            if (!Verifies(installation.Jwk, payload, Wire.Text(body["report_signature"])))
            {
                throw new Refusal(401, "invalid_installation_signature", "The signature does not verify.");
            }
            // 10. Used, in the same unit of work.
            challenge.Used = true;
        }
        // Only then are the measurements read: first, whether they are the contract's.
        var evaluation = schema.Evaluate(JsonDocument.Parse(payload).RootElement,
            new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (!evaluation.IsValid)
        {
            var at = evaluation.Details?.FirstOrDefault(d => !d.IsValid)?.InstanceLocation.ToString() ?? "";
            throw new Refusal(400, "report_not_accepted", "The report is not the contract's.",
                new JsonObject { ["check"] = "schema", ["at"] = at });
        }
        var reportId = Guid.NewGuid().ToString();
        lock (_lock)
        {
            _reports[reportId] = new StoredReport
            {
                InstallationId = session.InstallationId, At = Wire.Now(),
                OperationSha256 = challenge.OperationSha256, Session = challenge.Session,
            };
        }
        // Your business logic decides; the answer says what to do next, never a score
        // or a reason (section 7).
        return new JsonObject { ["integrity"] = new JsonObject { ["report_id"] = reportId, ["next"] = "allow" } };
    }

    // --- Section 2: a scan for one action, used by the request it named.

    private void RequireOperationScan(Call call)
    {
        var here = Wire.Sha256Hex(Wire.Canonical(new JsonObject
        {
            ["method"] = call.Method, ["path"] = call.Path, ["query"] = call.Query,
            ["body_sha256"] = Wire.Sha256Hex(call.Body),
        }));
        lock (_lock)
        {
            if (!_reports.TryGetValue(call.Header("X-Integrity-Report") ?? "", out var stored) || stored.Used
                || stored.OperationSha256 != here || stored.Session != call.Bearer
                || Wire.Now() - stored.At > OperationScanSeconds)
            {
                throw new Refusal(403, "needs_scan", "This request needs a scan made for it.");
            }
            stored.Used = true;
        }
    }

    // --- Section 3: step-up.

    private static void RequireStepUp(Call call, Session session, Installation installation, string nonce)
    {
        var proofText = call.Header("X-Step-Up-Proof");
        var signature = call.Header("X-Step-Up-Signature");
        if (string.IsNullOrEmpty(proofText) || string.IsNullOrEmpty(signature) || installation.StepUp is not { } stepUp)
        {
            throw new Refusal(403, "needs_step_up", "This request needs the person's approval.");
        }
        byte[] raw = [];
        JsonObject proof = new();
        try
        {
            raw = Wire.Decode(proofText);
            proof = JsonNode.Parse(raw) as JsonObject ?? new JsonObject();
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            // Fails the signature below.
        }
        if (!Verifies(stepUp.Jwk, raw, signature))
        {
            throw new Refusal(403, "step_up_not_accepted", "The approval does not verify.",
                new JsonObject { ["check"] = "signature" });
        }
        var expected = new (string Field, JsonNode Value)[]
        {
            ("version", 2), ("purpose", "stepup"), ("installation_id", session.InstallationId),
            ("access_token_sha256", Wire.Sha256Hex(call.Bearer!)), ("method", call.Method), ("path", call.Path),
            ("query", call.Query), ("body_sha256", Wire.Sha256Hex(call.Body)), ("nonce", nonce),
            // The factor this sample requires is the one the key was made with.
            ("factor", stepUp.Factor),
        };
        foreach (var (field, value) in expected)
        {
            if (!JsonNode.DeepEquals(proof[field], value))
            {
                throw new Refusal(403, "step_up_not_accepted", "The approval is for another request.",
                    new JsonObject { ["check"] = field });
            }
        }
        var timestamp = Wire.Integer(proof["timestamp"]);
        if (timestamp is null || Math.Abs(Wire.Now() - timestamp.Value) > ClockWindowSeconds)
        {
            throw new Refusal(403, "step_up_not_accepted", "The approval is out of time.",
                new JsonObject { ["check"] = "timestamp" });
        }
    }

    // --- Section 3: the app PIN.

    private Account AccountOf(Session session)
    {
        lock (_lock)
        {
            return _accounts[session.Account!];
        }
    }

    public async Task<JsonObject> SetAppPin(Call call, JsonObject body)
    {
        var (session, _, _) = Authenticate(call, "account");
        var account = AccountOf(session);
        await Reauthenticate(account, session.Account!, Wire.Text(body["password"]));
        var pin = Wire.Text(body["pin"]);
        if (pin is null || pin.Length != PinLength || !pin.All(char.IsAsciiDigit))
        {
            throw new Refusal(400, "bad_request", $"The PIN is {PinLength} digits.", new JsonObject { ["field"] = "pin" });
        }
        var (salt, verifier) = await SlowVerifierAsync(_pinSecret, session.Account!, pin);
        lock (_lock)
        {
            // A new PIN clears the wrong ones and any lock.
            account.PinSalt = salt;
            account.PinVerifier = verifier;
            account.PinFailures = 0;
            account.PinLocked = false;
        }
        return new JsonObject { ["app_pin_set"] = true };
    }

    public async Task<JsonObject> ProveAppPin(Call call, JsonObject body)
    {
        var (session, _, _) = Authenticate(call, "account");
        var pin = Wire.Text(body["pin"]);
        var target = body["request"] as JsonObject;
        bool complete;
        try
        {
            complete = !string.IsNullOrEmpty(pin) && target is not null
                && OperationValid(new JsonObject
                {
                    ["method"] = target["method"]?.DeepClone(), ["path"] = target["path"]?.DeepClone(),
                    ["query"] = target["query"]?.DeepClone(), ["body_sha256"] = target["body_sha256"]?.DeepClone(),
                })
                && Wire.Decode(Wire.Text(target["nonce"])).Length == 32;
        }
        catch (FormatException)
        {
            complete = false;
        }
        if (!complete)
        {
            // Refused before the PIN is checked.
            throw new Refusal(400, "bad_request", "Send the PIN and the request it unlocks.", new JsonObject { ["field"] = "request" });
        }
        var account = AccountOf(session);
        byte[] salt, verifier;
        lock (_lock)
        {
            if (account.PinVerifier is null || account.PinSalt is null)
            {
                throw new Refusal(403, "app_pin_not_set", "No app PIN is set for this account.");
            }
            if (account.PinLocked)
            {
                throw new Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.");
            }
            if (account.PinFailures + account.PinChecking >= PinAttempts)
            {
                // The attempts left are held by checks still running.
                throw new Refusal(429, "pin_busy", "The PIN is being checked; try again in a moment.",
                    new JsonObject { ["retry_after_seconds"] = 1 });
            }
            account.PinChecking += 1;   // the attempt, claimed before comparing
            salt = account.PinSalt;
            verifier = account.PinVerifier;
        }
        bool right;
        try
        {
            right = Wire.Same((await SlowVerifierAsync(_pinSecret, session.Account!, pin!, salt)).Verifier, verifier);
        }
        finally
        {
            lock (_lock)
            {
                account.PinChecking -= 1;
            }
        }
        bool locked;
        lock (_lock)
        {
            if (right)
            {
                account.PinFailures = 0;
            }
            else
            {
                account.PinFailures += 1;
                account.PinLocked = account.PinFailures >= PinAttempts;
            }
            locked = account.PinLocked;
        }
        if (!right)
        {
            throw locked
                ? new Refusal(403, "app_pin_locked", "The app PIN is locked; set a new one.")
                : new Refusal(403, "app_pin_invalid", "The app PIN is wrong.");
        }
        var expires = Wire.Now() + PinProofSeconds;
        var claims = Wire.Canonical(new JsonObject
        {
            ["account"] = session.Account, ["installation_id"] = session.InstallationId,
            ["session_sha256"] = Wire.Sha256Hex(call.Bearer!), ["request"] = target!.DeepClone(), ["expires_at"] = expires,
        });
        return new JsonObject
        {
            ["app_pin_proof"] = $"{Wire.Encode(claims)}.{Wire.Encode(Wire.Hmac(_pinProofKey, claims))}",
            ["expires_at"] = Wire.Iso(expires),
        };
    }

    private void RequireAppPin(Call call, Session session, string nonce)
    {
        JsonObject? proof = null;
        try
        {
            var parts = (call.Header("X-App-PIN-Proof") ?? "").Split('.');
            if (parts.Length == 2)
            {
                var claims = Wire.Decode(parts[0]);
                if (Wire.Same(Wire.Decode(parts[1]), Wire.Hmac(_pinProofKey, claims)))
                {
                    proof = JsonNode.Parse(claims) as JsonObject;
                }
            }
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            proof = null;
        }
        if (proof is null)
        {
            throw new Refusal(403, "needs_app_pin", "This request needs the app PIN.");
        }
        var expires = Wire.Integer(proof["expires_at"]);
        proof.Remove("expires_at");
        var expected = new JsonObject
        {
            ["account"] = session.Account, ["installation_id"] = session.InstallationId,
            ["session_sha256"] = Wire.Sha256Hex(call.Bearer!),
            ["request"] = new JsonObject
            {
                ["method"] = call.Method, ["path"] = call.Path, ["query"] = call.Query,
                ["body_sha256"] = Wire.Sha256Hex(call.Body), ["nonce"] = nonce,
            },
        };
        if (expires is null || expires < Wire.Now() || !Wire.Canonical(proof).SequenceEqual(Wire.Canonical(expected)))
        {
            throw new Refusal(403, "app_pin_not_accepted", "The PIN's proof is for another request.");
        }
    }

    // --- This sample's own account API, in which the plugin's proofs are used.

    public async Task<JsonObject> SignIn(Call call, JsonObject body)
    {
        var (session, _, _) = Authenticate(call, "installation");
        var handle = Wire.Text(body["handle"]);
        var password = Wire.Text(body["password"]);
        if (string.IsNullOrEmpty(handle) || string.IsNullOrEmpty(password))
        {
            throw new Refusal(400, "bad_request", "A handle and a password are required.");
        }
        Account? account;
        lock (_lock)
        {
            _accounts.TryGetValue(handle, out account);
        }
        if (account is null)
        {
            var (salt, verifier) = await SlowVerifierAsync(_passwordSecret, handle, password);
            lock (_lock)
            {
                if (!_accounts.TryGetValue(handle, out account))
                {
                    account = new Account { PasswordSalt = salt, PasswordVerifier = verifier };
                    _accounts[handle] = account;
                }
            }
        }
        await Reauthenticate(account, handle, password);
        var token = Wire.Encode(RandomNumberGenerator.GetBytes(32));
        lock (_lock)
        {
            // An account session for this installation, which proved its key.
            _sessions[token] = new Session
            {
                Kind = "account", InstallationId = session.InstallationId, Account = handle, Expires = Wire.Now() + SessionSeconds,
            };
        }
        return new JsonObject { ["account_session"] = token };
    }

    private async Task Reauthenticate(Account account, string handle, string? password)
    {
        var (_, verifier) = await SlowVerifierAsync(_passwordSecret, handle, password ?? "", account.PasswordSalt);
        if (!Wire.Same(verifier, account.PasswordVerifier))
        {
            throw new Refusal(401, "reauthentication_failed", "The password is wrong.");
        }
    }

    public JsonObject Demo(Call call, params string[] needs)
    {
        var (session, installation, nonce) = Authenticate(call, "account");
        if (needs.Contains("scan"))
        {
            RequireOperationScan(call);
        }
        if (needs.Contains("approval"))
        {
            // The person's approval, as the request offers it: step-up, the app PIN, or both -- and
            // each one offered must hold.
            var stepUp = !string.IsNullOrEmpty(call.Header("X-Step-Up-Proof"));
            var appPin = !string.IsNullOrEmpty(call.Header("X-App-PIN-Proof"));
            if (!stepUp && !appPin)
            {
                throw new Refusal(403, "needs_approval",
                    "This request needs the person's approval: step-up or the app PIN.");
            }
            if (stepUp)
            {
                RequireStepUp(call, session, installation, nonce);
            }
            if (appPin)
            {
                RequireAppPin(call, session, nonce);
            }
        }
        return new JsonObject { ["done"] = call.Path };
    }

    // --- Test controls, on only with --test-controls.

    public JsonObject Control(string path, JsonObject body)
    {
        lock (_lock)
        {
            switch (path)
            {
                case "/test/expire-sessions":
                    foreach (var session in _sessions.Values)
                    {
                        session.Expires = Wire.Now() - 1;
                    }
                    break;
                case "/test/forget":
                    var id = Wire.Text(body["installation_id"]) ?? "";
                    if (_installations.Remove(id, out var record))
                    {
                        _byThumbprint.Remove(record.Thumbprint);
                    }
                    break;
                case "/test/refuse-next":
                    _pending[Wire.Text(body["path"]) ?? ""] = (JsonObject)body.DeepClone();
                    break;
                default:
                    throw new Refusal(404, "no_such_path", "No such control.");
            }
        }
        return new JsonObject { ["ok"] = true };
    }

    public JsonObject? TakePending(string path)
    {
        lock (_lock)
        {
            return _pending.Remove(path, out var pending) ? pending : null;
        }
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        string? Option(string name) => Array.IndexOf(args, name) is var at and >= 0 && at + 1 < args.Length ? args[at + 1] : null;
        var schemaPath = Option("--schema");
        if (schemaPath is null)
        {
            Console.Error.WriteLine("usage: SampleBackend --schema <contract>/report.schema.json [--port 8787] [--test-controls]");
            Environment.Exit(2);
        }
        var port = int.Parse(Option("--port") ?? "8787");
        // Test controls answer only requests carrying X-Test-Token: $SAMPLE_TEST_TOKEN.
        var testToken = args.Contains("--test-controls")
            ? Environment.GetEnvironmentVariable("SAMPLE_TEST_TOKEN") ?? "" : null;
        if (testToken is not null && testToken.Length < 16)
        {
            Console.Error.WriteLine("--test-controls needs SAMPLE_TEST_TOKEN, 16 characters or more");
            Environment.Exit(2);
        }
        var backend = new Backend(JsonSchema.FromText(File.ReadAllText(schemaPath)), testToken);

        var builder = WebApplication.CreateSlimBuilder();
        // ASP.NET Core logs nothing; the handler logs one line per call, never a body or a header.
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        var app = builder.Build();

        app.Run(async context => await Handle(backend, context));
        Console.WriteLine($"listening on http://127.0.0.1:{port}");
        app.Run();
    }

    private static readonly Dictionary<string, Func<Backend, Call, JsonObject, Task<JsonObject>>> Routes = new()
    {
        ["/v1/installations/register"] = (b, c, body) => Task.FromResult(b.Register(body)),
        ["/v1/installations/challenge"] = (b, c, body) => Task.FromResult(b.KeyChallenge(body)),
        ["/v1/installations/verify"] = (b, c, body) => Task.FromResult(b.Verify(body)),
        ["/v1/integrity/challenge"] = (b, c, body) => Task.FromResult(b.ScanChallengeFor(c, body)),
        ["/v1/integrity/report"] = (b, c, body) => Task.FromResult(b.Report(c, body)),
        ["/v1/account/app-pin"] = (b, c, body) => b.SetAppPin(c, body),
        ["/v1/account/app-pin/proof"] = (b, c, body) => b.ProveAppPin(c, body),
        ["/v1/demo/sign-in"] = (b, c, body) => b.SignIn(c, body),
        ["/v1/demo/echo"] = (b, c, body) => Task.FromResult(b.Demo(c)),
        ["/v1/demo/transfer"] = (b, c, body) => Task.FromResult(b.Demo(c, "scan")),
        ["/v1/demo/sensitive"] = (b, c, body) => Task.FromResult(b.Demo(c, "approval")),
    };

    private static async Task Handle(Backend backend, HttpContext context)
    {
        // The request target exactly as sent: the proofs sign it so.
        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "/";
        var at = target.IndexOf('?');
        using var buffer = new MemoryStream();
        await context.Request.Body.CopyToAsync(buffer);
        var call = new Call(context.Request.Method, at < 0 ? target : target[..at], at < 0 ? "" : target[(at + 1)..],
            context.Request.Headers, buffer.ToArray());
        int status = 200;
        JsonNode answer;
        try
        {
            if (call.Method == "GET" && call.Path == "/health")
            {
                answer = new JsonObject { ["ok"] = true };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(answer.ToJsonString());
                return;
            }
            if (call.Method != "POST")
            {
                throw new Refusal(404, "no_such_path", "No such path.");
            }
            JsonObject body;
            try
            {
                body = call.Body.Length == 0 ? new JsonObject()
                    : JsonNode.Parse(call.Body) as JsonObject ?? throw new Refusal(400, "bad_request", "The body is not a JSON object.");
            }
            catch (JsonException)
            {
                throw new Refusal(400, "bad_request", "The body is not JSON.");
            }
            if (call.Path.StartsWith("/test/", StringComparison.Ordinal) && backend.TestTokenMatches(call.Header("X-Test-Token")))
            {
                answer = backend.Control(call.Path, body);
            }
            else if (backend.TakePending(call.Path) is { } pending)
            {
                throw new Refusal((int)(Wire.Integer(pending["status"]) ?? 400), Wire.Text(pending["code"]) ?? "refused",
                    "Refused for a test.", pending["details"]?.DeepClone() as JsonObject);
            }
            else if (Routes.TryGetValue(call.Path, out var route))
            {
                answer = await route(backend, call, body);
            }
            else
            {
                throw new Refusal(404, "no_such_path", "No such path.");
            }
        }
        catch (Refusal refusal)
        {
            status = refusal.Status;
            var error = new JsonObject { ["code"] = refusal.Code, ["message"] = refusal.Message };
            if (refusal.Details is not null)
            {
                error["details"] = refusal.Details;
            }
            answer = new JsonObject { ["error"] = error };
        }
        // One line per call: the method, the path, the status and any refusal's code;
        // never a body or a header -- they hold PINs.
        Console.WriteLine($"{call.Method} {call.Path} {status} {Wire.Text(answer["error"]?["code"]) ?? ""}");
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(answer.ToJsonString());
    }
}
