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

// --- The contract's rules (RULES.md): what a report's measurements are worth before any business
// logic weighs them -- never a score. A report is judged over the measurements its challenge required:
// complete, partial (part of the app's code compared), incomplete (something not measured) or invalid
// (figures that cannot all be true).
public static class Contract
{
    public static readonly string[] Qualities = ["complete", "partial", "incomplete", "invalid"];   // best to worst

    // Where code is always mapped, so that a comparison there finds some (RULES.md 4): on an iPhone only
    // the app's own, the rest being unreadable.
    private static readonly Dictionary<string, string[]> Regions = new()
    {
        ["android"] = ["core", "ext", "app"],
        ["ios"] = ["app"],
    };

    private static readonly string[] IosCoverage =
        ["app_images_expected", "app_images_compared", "app_images_unreadable", "app_images_skipped",
            "app_expected_bytes", "app_compared_bytes", "app_unreadable_bytes", "app_skipped_bytes",
            "app_complete", "main_executable_compared"];

    private static bool Absent(JsonNode? node) => node is null || node.GetValueKind() == JsonValueKind.Null;

    private static bool? Flag(JsonNode? node) =>
        node is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False ? v.GetValue<bool>() : null;

    private static IEnumerable<string> Listed(JsonObject definition, string key) =>
        definition[key] is JsonArray fields ? fields.Select(f => Wire.Text(f) ?? "") : [];

    /// <summary>The contract's judgment of a report whose shape the schema accepted. Split APKs out of
    /// order (RULES.md 6, the one rule a schema cannot state) are refused rather than read.</summary>
    public static string Judge(JsonObject report, IEnumerable<string> required, JsonObject definitions)
    {
        var platform = Wire.Text(report["platform"]) ?? "";
        var results = report["probe_results"] as JsonObject ?? new JsonObject();
        if ((results["app_identity"] as JsonObject)?["split_apks"] is JsonArray splits)
        {
            var names = splits.Select(entry => Wire.Text(entry?["name"]) ?? "").ToArray();
            // Sorted by name, ordinally, none twice.
            if (names.Where((name, at) => at > 0 && string.CompareOrdinal(names[at - 1], name) >= 0).Any())
            {
                throw new Refusal(400, "report_not_accepted", "The report is not the contract's.",
                    new JsonObject { ["check"] = "split_apks" });
            }
        }
        var found = new List<string> { "complete" };
        foreach (var name in required)
        {
            var definition = definitions[$"{platform}.{name}"] as JsonObject ?? new JsonObject();
            if (results[name] is not JsonObject value || Wire.Text(value["status"]) != "ok")
            {
                found.Add("incomplete");   // failed or unsupported: not measured (2)
                continue;
            }
            // ok is a claim: a measurement is complete with every field it lists, and with nothing in
            // unread (2).
            if (Listed(definition, "x-complete-when-ok").Any(field => Absent(value[field]))
                || (value["unread"] is JsonObject unread && unread.Count > 0))
            {
                found.Add("incomplete");
            }
            // Failed reads, not clean values (7).
            if ((name is "runtime_maps" or "exec_mappings" && Wire.Integer(value["maps_lines"]) == 0)
                || (name == "instrumentation_threads" && Wire.Integer(value["thread_count"]) == 0))
            {
                found.Add("incomplete");
            }
            if (name == "exec_mappings" && WxSizesWithoutMappings(value))
            {
                found.Add("invalid");
            }
            if (name == "code_integrity")
            {
                found.Add(CodeComparison(platform, value, definition));
            }
        }
        // Contradictions across measurements (7).
        if (results["screen_capture"] is JsonObject capture && Wire.Text(capture["status"]) == "ok"
            && Wire.Text(capture["recording_status"]) == "unsupported"
            && (platform == "ios" || (results["device"] is JsonObject device && Wire.Integer(device["sdk_int"]) >= 35)))
        {
            found.Add("invalid");   // recording unsupported where it is measured
        }
        if (results["location"] is JsonObject location && results["mock_location"] is JsonObject mock
            && Wire.Text(location["status"]) == "ok" && Wire.Text(mock["status"]) == "ok"
            && Wire.Integer(location["fix_time"]) is { } locationTime && Wire.Integer(mock["fix_time"]) is { } mockTime
            && locationTime != mockTime)
        {
            found.Add("invalid");   // two fixes presented as one (5)
        }
        return found.MaxBy(quality => Array.IndexOf(Qualities, quality))!;
    }

    /// <summary>No writable-and-executable mapping, with the sizes of such mappings listed (RULES.md 7).</summary>
    private static bool WxSizesWithoutMappings(JsonObject maps)
    {
        var classes = 0;
        foreach (var part in (Wire.Text(maps["wx_size_classes"]) ?? "").Split(','))
        {
            if (string.IsNullOrWhiteSpace(part))
            {
                continue;
            }
            var at = part.IndexOf(':');
            var size = (at < 0 ? part : part[..at]).Trim();
            var count = (at < 0 ? "" : part[(at + 1)..]).Trim();
            if (size.Length == 0 || count.Length == 0 || !size.All(char.IsAsciiDigit) || !count.All(char.IsAsciiDigit))
            {
                classes = 0;   // not a list of sizes
                break;
            }
            classes += 1;
        }
        var extremes = (Wire.Integer(maps["wx_smallest_bytes"]) ?? 0) != 0 || (Wire.Integer(maps["wx_largest_bytes"]) ?? 0) != 0;
        return Wire.Integer(maps["wx_mappings"]) == 0 && (Wire.Integer(maps["wx_bytes"]) ?? 0) == 0
            && (classes > 0 || extremes);
    }

    /// <summary>The comparison of code in memory with its files (RULES.md 4): invalid when its figures
    /// do not add up; incomplete when it did not run, lacks a figure, or compared nothing where code
    /// always is; partial when it compared part of the code.</summary>
    private static string CodeComparison(string platform, JsonObject code, JsonObject definition)
    {
        if (!(platform == "android" ? AndroidCoverageAddsUp(code) : IosCoverageAddsUp(code)))
        {
            return "invalid";
        }
        if (Flag(code["checked"]) != true || Listed(definition, "x-complete-when-checked").Any(field => Absent(code[field])))
        {
            return "incomplete";
        }
        if (Regions[platform].Any(region => Wire.Integer(code[$"{region}_compared_bytes"]) == 0))
        {
            return "incomplete";
        }
        if (platform == "ios")
        {
            return Flag(code["app_complete"]) == true ? "complete" : "partial";
        }
        var shortOf = Regions["android"].Any(region =>
            Wire.Integer(code[$"{region}_compared_bytes"]) < Wire.Integer(code[$"{region}_expected_bytes"]));
        return shortOf || (Wire.Integer(code["protect_restore_failures"]) ?? 0) > 0 ? "partial" : "complete";
    }

    /// <summary>In each region the expected bytes are the compared, skipped and unreadable ones together,
    /// and &lt;region&gt;_complete is true exactly when some code was expected and all of it was
    /// compared.</summary>
    private static bool AndroidCoverageAddsUp(JsonObject code)
    {
        foreach (var region in Regions["android"])
        {
            if (Absent(code[$"{region}_expected_bytes"]))
            {
                continue;
            }
            var expected = Wire.Integer(code[$"{region}_expected_bytes"]);
            var parts = new[] { "compared", "skipped", "unreadable" }.Select(kind => Wire.Integer(code[$"{region}_{kind}_bytes"])).ToArray();
            if (expected is null || parts.Any(part => part is null) || parts.Sum() != expected)
            {
                return false;
            }
            if (Flag(code[$"{region}_complete"]) is { } complete && complete != (expected > 0 && parts[0] == expected))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Images and bytes both add up -- expected = compared + unreadable + skipped -- and
    /// app_complete is true exactly when every image was compared, the main executable among them; bytes
    /// are compared exactly when images are, and each image not compared is named. A collector that
    /// reports only part of it is judged by its fields instead.</summary>
    private static bool IosCoverageAddsUp(JsonObject code)
    {
        if (IosCoverage.Any(field => Absent(code[field])))
        {
            return true;
        }
        var figures = IosCoverage.Take(8).Select(field => Wire.Integer(code[field])).ToArray();
        if (figures.Any(figure => figure is null))
        {
            return false;
        }
        long expected = figures[0]!.Value, compared = figures[1]!.Value, unreadable = figures[2]!.Value, skipped = figures[3]!.Value;
        long expectedBytes = figures[4]!.Value, comparedBytes = figures[5]!.Value, unreadableBytes = figures[6]!.Value,
            skippedBytes = figures[7]!.Value;
        var complete = expected > 0 && compared == expected;
        var main = Flag(code["main_executable_compared"]);
        var named = code["app_images_not_compared"];
        var namedCount = named is JsonObject list ? list.Count : 0;
        var checkedFlag = Flag(code["checked"]);
        return !(
            expected != compared + unreadable + skipped
            || expectedBytes != comparedBytes + unreadableBytes + skippedBytes
            || Flag(code["app_complete"]) != complete
            || (complete && (unreadableBytes > 0 || skippedBytes > 0))
            || (unreadableBytes > 0 && unreadable == 0) || (skippedBytes > 0 && skipped == 0)
            || (comparedBytes > 0) != (compared > 0)
            || (!Absent(code["checked"]) && checkedFlag != (compared > 0))
            || (main == true && compared == 0) || (complete && main != true)
            || (!Absent(named) && (namedCount > unreadable + skipped || (unreadable + skipped > 0 && namedCount == 0))));
    }

    // Your business logic decides (the guide, section 7), and this is where it goes. This sample decides
    // on the contract's judgment alone and scores nothing: a complete report lets the action go on, and
    // so -- by this sample's choice -- does a partial one, whose comparison found nothing in the code it
    // could read; an incomplete one asks for a scan again, since a failed read is no proof of an attack;
    // and a report whose figures contradict each other is held for review. Only a report allowed here
    // approves a scan made for one action.
    private static readonly Dictionary<string, string> Next = new()
    {
        ["complete"] = "allow", ["partial"] = "allow", ["incomplete"] = "scan_again", ["invalid"] = "review",
    };

    /// <summary>What to do next, for this report: allow, scan_again or review.</summary>
    public static string Decide(string judgment, JsonObject report) => Next[judgment];
}

/// <summary>A step-up key; a re-enrolled one carries the account that re-enrolled it.</summary>
public sealed record StepUpKey(JsonObject Jwk, string Factor, string Mode, long WindowSeconds, string? Account = null);

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
    // Each PIN set is a new generation; a check settles against the one it compared.
    public int PinGeneration { get; set; }
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
    public required string Judgment { get; init; }
    public required string Next { get; init; }
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

public sealed class Backend(JsonSchema schema, JsonObject definitions, string? testToken)
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

    // What this sample asks for in every scan: every measurement that would catch tampering, the
    // hooks, gadgets and changes to the app's code in memory among them. One left to chance is one a
    // tampered app waits out, scanning again until it is not drawn. Only what weighs little varies.
    private static readonly Dictionary<string, string[]> ReliedOn = new()
    {
        ["android"] = ["app_identity", "debug_state", "tracer", "root_files", "root_shell", "system_properties",
            "selinux", "mounts", "developer_settings",
            // Hooks and gadgets by name, by port, by thread and by memory layout; and the code in
            // memory compared with its file.
            "runtime_maps", "frida_ports", "instrumentation_threads", "exec_mappings", "code_integrity"],
        ["ios"] = ["app_identity", "code_signing", "debugger", "jailbreak_files", "sandbox",
            // Injected libraries, and the app's code in memory compared with its file -- asked for,
            // so that a report without it is refused.
            "dyld_images", "environment", "code_integrity"],
    };

    private static readonly Dictionary<string, string[]> Varied = new()
    {
        ["android"] = ["emulator"],
        ["ios"] = ["simulator"],
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
    // Test control: while set, PIN checks wait on it; released with fail, their verifier fails.
    private TaskCompletionSource<bool>? _pinGate;
    private int _pinWaiting;   // test control: the PIN checks waiting now

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
                // re-enrolment replaces one -- so the answer says whether it is the one held,
                // and the app asks for re-enrolment rather than sign with a key this backend lacks.
                var bound = _installations[held].StepUp;
                return new JsonObject
                {
                    ["installation_id"] = held, ["stepup_key_registered"] = bound is not null,
                    ["stepup_key_matches"] = stepUp is null ? null
                        : bound is not null && Thumbprint(bound.Jwk) == Thumbprint(stepUp.Jwk),
                };
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
        return new JsonObject { ["installation_id"] = installationId, ["stepup_key_registered"] = stepUp is not null };
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
        // Each of the others on about half the scans, unpredictably.
        var required = ReliedOn[platform]
            .Concat(Varied[platform].Where(_ => RandomNumberGenerator.GetInt32(2) == 1)).ToArray();
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
        CheckShape(report);
        // Then what they are worth, by the contract's rules; then the decision.
        var judgment = Contract.Judge(report, challenge.Required, definitions);
        var decision = Contract.Decide(judgment, report);
        var reportId = Guid.NewGuid().ToString();
        lock (_lock)
        {
            _reports[reportId] = new StoredReport
            {
                InstallationId = session.InstallationId, At = Wire.Now(),
                OperationSha256 = challenge.OperationSha256, Session = challenge.Session,
                Judgment = judgment, Next = decision,
            };
        }
        // The answer says what to do next, never the judgment, a score or a reason (section 7).
        return new JsonObject { ["integrity"] = new JsonObject { ["report_id"] = reportId, ["next"] = decision } };
    }

    /// <summary>The report against the contract's schema: its shape.</summary>
    private void CheckShape(JsonObject report)
    {
        var evaluation = schema.Evaluate(JsonDocument.Parse(report.ToJsonString()).RootElement,
            new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (!evaluation.IsValid)
        {
            var at = evaluation.Details?.FirstOrDefault(d => !d.IsValid)?.InstanceLocation.ToString() ?? "";
            throw new Refusal(400, "report_not_accepted", "The report is not the contract's.",
                new JsonObject { ["check"] = "schema", ["at"] = at });
        }
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
            // A scan made for this request, under this session, lately -- and one the decision allowed.
            if (!_reports.TryGetValue(call.Header("X-Integrity-Report") ?? "", out var stored) || stored.Used
                || stored.OperationSha256 != here || stored.Session != call.Bearer
                || Wire.Now() - stored.At > OperationScanSeconds || stored.Next != "allow")
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
        // A re-enrolled key approves for the account that re-enrolled it alone.
        if (stepUp.Account is not null && stepUp.Account != session.Account)
        {
            throw new Refusal(403, "step_up_not_accepted", "The step-up key is another account's.",
                new JsonObject { ["check"] = "account" });
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

    // --- Section 3: re-enrolment, a new step-up key for this account alone.

    public async Task<JsonObject> ReenrolStepUp(Call call, JsonObject body)
    {
        var (session, installation, nonce) = Authenticate(call, "account");
        var stepUp = StepUpKeyOf(body, installation.Thumbprint)
            ?? throw new Refusal(400, "bad_request", "A new step-up key is required.",
                new JsonObject { ["field"] = "stepup_public_key" });
        byte[] raw = [];
        JsonObject proof = new();
        try
        {
            raw = Wire.Decode(Wire.Text(body["stepup_key_proof"]) ?? "");
            proof = JsonNode.Parse(raw) as JsonObject ?? new JsonObject();
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            // Fails the signature below.
        }
        // Every check of the new key before the password, so that this call cannot serve to guess it.
        if (!Verifies(stepUp.Jwk, raw, Wire.Text(body["stepup_key_signature"])))
        {
            throw new Refusal(403, "step_up_not_accepted", "The new key's proof does not verify.",
                new JsonObject { ["check"] = "signature" });
        }
        var expected = new (string Field, JsonNode Value)[]
        {
            ("version", 1), ("purpose", "stepup_reenrol"), ("installation_id", session.InstallationId),
            ("stepup_key_thumbprint", Thumbprint(stepUp.Jwk)), ("nonce", nonce),
        };
        foreach (var (field, value) in expected)
        {
            if (!JsonNode.DeepEquals(proof[field], value))
            {
                throw new Refusal(403, "step_up_not_accepted", "The new key's proof is for another request.",
                    new JsonObject { ["check"] = field });
            }
        }
        var timestamp = Wire.Integer(proof["timestamp"]);
        if (timestamp is null || Math.Abs(Wire.Now() - timestamp.Value) > ClockWindowSeconds)
        {
            throw new Refusal(403, "step_up_not_accepted", "The new key's proof is out of time.",
                new JsonObject { ["check"] = "timestamp" });
        }
        await Reauthenticate(AccountOf(session), session.Account!, Wire.Text(body["password"]));
        lock (_lock)
        {
            // Another account on the phone, which needs only the installation key, gains no step-up from it.
            _installations[session.InstallationId] = installation with { StepUp = stepUp with { Account = session.Account } };
        }
        return new JsonObject { ["stepup_key_registered"] = true };
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
            // A new PIN clears the wrong ones and any lock, and is a new generation: checks of the
            // PIN it replaces settle against that one, and the proofs made under it no longer serve.
            account.PinSalt = salt;
            account.PinVerifier = verifier;
            account.PinFailures = 0;
            account.PinLocked = false;
            account.PinChecking = 0;
            account.PinGeneration += 1;
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
        int generation;
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
            generation = account.PinGeneration;
            salt = account.PinSalt;
            verifier = account.PinVerifier;
        }
        bool? right;
        try
        {
            await HeldPinCheck();
            right = Wire.Same((await SlowVerifierAsync(_pinSecret, session.Account!, pin!, salt)).Verifier, verifier);
        }
        catch (Exception)
        {
            right = null;   // the check could not run
        }
        bool current, locked;
        lock (_lock)
        {
            // Settled in one step -- the attempt given back and the PIN's count changed under one
            // lock, so that no other check takes the attempt between -- against the PIN it compared:
            // a PIN set meanwhile is left alone -- its count, its lock, its checks -- and a check
            // that could not run gives its attempt back.
            current = account.PinGeneration == generation;
            if (current)
            {
                account.PinChecking -= 1;
                if (right == true)
                {
                    account.PinFailures = 0;
                }
                else if (right == false)
                {
                    account.PinFailures += 1;
                    account.PinLocked = account.PinFailures >= PinAttempts;
                }
            }
            locked = account.PinLocked;
        }
        if (right is null)
        {
            throw new Refusal(503, "pin_unavailable", "The app PIN cannot be checked now; try again.");
        }
        if (!current)
        {
            // Neither a proof nor a count: the PIN it was right or wrong for is no longer the account's.
            throw new Refusal(403, "app_pin_invalid", "The app PIN was changed while it was checked; enter it again.");
        }
        if (right == false)
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
            ["pin_generation"] = generation,
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
        int generation;
        lock (_lock)
        {
            generation = _accounts[session.Account!].PinGeneration;
        }
        if (Wire.Integer(proof["pin_generation"]) != generation)
        {
            throw new Refusal(403, "app_pin_not_accepted", "The app PIN was changed since this proof was made; enter it again.");
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
            ["pin_generation"] = generation,
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

    /// <summary>A PIN check waits here, its attempt claimed, while a test holds PIN checks; released
    /// with fail, its verifier fails.</summary>
    private async Task HeldPinCheck()
    {
        TaskCompletionSource<bool>? gate;
        lock (_lock)
        {
            gate = _pinGate;
            if (gate is null)
            {
                return;
            }
            _pinWaiting += 1;
        }
        var fail = await gate.Task;
        lock (_lock)
        {
            _pinWaiting -= 1;
        }
        if (fail)
        {
            throw new InvalidOperationException("the verifier failed, for a test");
        }
    }

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
                case "/test/judge":
                    // The contract's judgment of a report under a plan of the test's own, as the report
                    // call would make it.
                    try
                    {
                        var report = (JsonObject)body["report"]!;
                        CheckShape(report);
                        var required = ((JsonArray)body["required_probes"]!).Select(p => Wire.Text(p) ?? "");
                        return new JsonObject { ["judged"] = Contract.Judge(report, required, definitions) };
                    }
                    catch (Refusal)
                    {
                        return new JsonObject { ["judged"] = "refused" };
                    }
                case "/test/pin-checks":
                    // Hold PIN checks once they claim their attempt, or release those waiting; the
                    // answer counts those waiting.
                    var hold = body["hold"] is JsonValue held && held.TryGetValue(out bool on) ? on : (bool?)null;
                    if (hold == true && _pinGate is null)
                    {
                        _pinGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    }
                    else if (hold == false && _pinGate is not null)
                    {
                        _pinGate.SetResult(body["fail"] is JsonValue fail && fail.TryGetValue(out bool failed) && failed);
                        _pinGate = null;
                    }
                    return new JsonObject { ["ok"] = true, ["waiting"] = _pinWaiting };
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
        var schemaText = File.ReadAllText(schemaPath);
        var definitions = JsonNode.Parse(schemaText)?["$defs"] as JsonObject ?? new JsonObject();   // the x- annotations
        var backend = new Backend(JsonSchema.FromText(schemaText), definitions, testToken);

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
        ["/v1/installations/stepup-key"] = (b, c, body) => b.ReenrolStepUp(c, body),
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
        var failed = "";
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
            // Which check failed goes to the log, never to the phone, which is told what to do next
            // (section 7): what gave a request away is what an attacker would fix.
            var details = refusal.Details?.DeepClone() as JsonObject ?? new JsonObject();
            failed = string.Join(" ", new[] { "check", "at" }
                .Where(key => details.ContainsKey(key))
                .Select(key => $"{key}={(details[key] is JsonValue value ? value.ToString() : "")}"));
            details.Remove("check");
            details.Remove("at");
            if (details.Count > 0)
            {
                error["details"] = details;
            }
            answer = new JsonObject { ["error"] = error };
        }
        // One line per call: the method, the path, the status, any refusal's code and the check
        // that failed; never a body or a header -- they hold PINs.
        Console.WriteLine($"{call.Method} {call.Path} {status} {Wire.Text(answer["error"]?["code"]) ?? ""} {failed}".TrimEnd());
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(answer.ToJsonString());
    }
}
