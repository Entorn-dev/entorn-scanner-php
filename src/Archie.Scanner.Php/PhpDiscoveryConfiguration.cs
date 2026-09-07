using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Archie.Scanner.Php;

internal static class PhpDiscoveryConfigurationReader
{
    private static readonly HashSet<string> RootProperties = ["schemaVersion", "modules"];
    private static readonly HashSet<string> ModuleProperties = ["path", "name"];

    public static async Task<PhpDiscoveryConfiguration?> ReadAsync(
        SourceFile file,
        PhpScannerLimits limits,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        try
        {
            using var document = JsonDocument.Parse(
                await File.ReadAllBytesAsync(file.FullPath, cancellationToken),
                new() { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(item => !RootProperties.Contains(item.Name)) ||
                !root.TryGetProperty("schemaVersion", out var schemaVersion) ||
                schemaVersion.ValueKind != JsonValueKind.String ||
                schemaVersion.GetString() != "php-discovery/v1" ||
                !root.TryGetProperty("modules", out var modules) ||
                modules.ValueKind != JsonValueKind.Array)
            {
                AddDiagnostic(diagnostics, "PHP_DISCOVERY_CONFIGURATION_INVALID",
                    "The PHP discovery configuration has an unsupported root shape or schema version and was not interpreted.",
                    file.Path);
                return null;
            }

            var configured = new List<ConfiguredModule>();
            var records = 0;
            foreach (var module in modules.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++records > limits.MaxConfiguredModules)
                    throw new PhpWorkerLimitException("PHP_CONFIGURED_MODULE_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded configured-module budget.");
                if (!TryReadModule(module, out var value))
                {
                    AddDiagnostic(diagnostics, "PHP_DISCOVERY_MODULE_INVALID",
                        "A PHP discovery module declaration is invalid and was not interpreted.",
                        $"{file.Path}:{records}");
                    continue;
                }
                configured.Add(value!);
            }

            foreach (var group in configured.GroupBy(item => item.Path, PathComparer()))
            {
                var names = group.Select(item => item.Name).Distinct(StringComparer.Ordinal).ToArray();
                if (names.Length <= 1) continue;
                AddDiagnostic(diagnostics, "PHP_DISCOVERY_CONFIGURATION_INVALID",
                    "The PHP discovery configuration declares conflicting names for one module path and was not interpreted.",
                    file.Path);
                return null;
            }

            return new(file.Path, configured.Distinct().OrderBy(item => item.Path, StringComparer.Ordinal).ToArray());
        }
        catch (JsonException)
        {
            AddDiagnostic(diagnostics, "PHP_DISCOVERY_CONFIGURATION_INVALID",
                "The PHP discovery configuration is not valid bounded JSON and was not interpreted.", file.Path);
            return null;
        }
    }

    private static bool TryReadModule(JsonElement module, out ConfiguredModule? configured)
    {
        configured = null;
        if (module.ValueKind != JsonValueKind.Object ||
            module.EnumerateObject().Any(item => !ModuleProperties.Contains(item.Name)) ||
            !module.TryGetProperty("path", out var pathProperty) ||
            pathProperty.ValueKind != JsonValueKind.String)
            return false;

        var path = NormalizePath(pathProperty.GetString());
        if (path is null) return false;
        string? name = null;
        if (module.TryGetProperty("name", out var nameProperty))
        {
            if (nameProperty.ValueKind != JsonValueKind.String) return false;
            name = nameProperty.GetString()?.Trim();
            if (string.IsNullOrEmpty(name) || name.Length > 128 || name.Any(char.IsControl)) return false;
        }

        configured = new(path, name);
        return true;
    }

    private static string? NormalizePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512 || Path.IsPathRooted(value) ||
            value.Any(char.IsControl) || value.Contains('*') || value.Contains('?') || value.Contains('#') ||
            value.Contains("://", StringComparison.Ordinal))
            return null;
        var segments = value.Replace('\\', '/').Split('/');
        if (segments.Any(item => item.Length == 0 || item is "." or ".." || item.Contains(':')))
            return null;
        return string.Join('/', segments);
    }

    private static void AddDiagnostic(
        ICollection<Diagnostic> diagnostics,
        string code,
        string message,
        string key) =>
        diagnostics.Add(new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}",
            code, "warning", message, null));

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private static StringComparer PathComparer() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}
