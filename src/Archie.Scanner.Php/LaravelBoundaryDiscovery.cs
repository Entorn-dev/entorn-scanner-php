using System.Security.Cryptography;
using System.Text;

namespace Archie.Scanner.Php;

internal static class LaravelBoundaryDiscovery
{
    private static readonly HashSet<string> PrefixMarkers =
        ["Domain", "Domains", "Module", "Modules", "BoundedContext", "BoundedContexts"];
    private static readonly HashSet<string> LayerMarkers = ["Domain", "Application", "Infrastructure"];

    public static BoundaryDiscoveryResult Discover(
        PhpProjectModel project,
        PhpScannerLimits limits,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<Diagnostic>();
        var deployable = new ApplicationBoundary(
            $"php:laravel-app:{project.ComposerPath}", project.Name, NodeKind.Deployable, project.RootPath, null,
            Confidence.Confirmed, Resolution.Resolved,
            new(EvidenceProvenance.Deterministic, project.ComposerPath, null,
                "composer:locked-laravel-application", Confidence.Confirmed), []);
        var candidates = new Dictionary<string, ApplicationBoundary>(PathComparer());

        foreach (var root in project.Psr4Roots.OrderBy(item => item.Path, StringComparer.Ordinal))
            foreach (var declaration in project.Index.Types.Values
                         .Where(item => IsWithinPath(item.Path, root.Path))
                         .OrderBy(item => item.Path, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = declaration.Path[(root.Path.Length + 1)..];
                var segments = relative.Split('/');
                string? moduleRoot = null;
                if (segments.Length >= 3 && PrefixMarkers.Contains(segments[0]))
                    moduleRoot = Combine(root.Path, $"{segments[0]}/{segments[1]}");
                else if (segments.Length >= 3 && LayerMarkers.Contains(segments[1]))
                    moduleRoot = Combine(root.Path, segments[0]);
                if (moduleRoot is null || candidates.ContainsKey(moduleRoot)) continue;
                candidates.Add(moduleRoot, Boundary(project, moduleRoot, FriendlyName(Path.GetFileName(moduleRoot)),
                    ModuleOrigin.Convention, Confidence.Inferred,
                    new(EvidenceProvenance.Deterministic, declaration.Path, declaration.Range,
                        "laravel:conventional-module-root", Confidence.Inferred)));
            }

        if (project.Configuration is not null)
        {
            foreach (var configured in project.Configuration.Modules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var moduleRoot = Combine(project.RootPath, configured.Path);
                var admitted = project.Psr4Roots.Any(root => IsWithinOrEqual(moduleRoot, root.Path)) &&
                    project.Index.Types.Values.Any(item => IsWithinPath(item.Path, moduleRoot));
                if (!admitted)
                {
                    diagnostics.Add(Diagnostic("PHP_DISCOVERY_MODULE_OUTSIDE_PRODUCTION_SOURCE",
                        "A configured PHP module does not own indexed production source and was not interpreted.",
                        project.Key, $"{project.Configuration.Path}:{configured.Path}"));
                    continue;
                }

                var supportingEvidence = candidates.TryGetValue(moduleRoot, out var inferred)
                    ? new[] { inferred.Evidence }.Concat(inferred.SupportingEvidence).ToArray()
                    : [];
                candidates[moduleRoot] = Boundary(project, moduleRoot,
                    configured.Name ?? FriendlyName(Path.GetFileName(moduleRoot)),
                    ModuleOrigin.Configuration, Confidence.Confirmed,
                    new(EvidenceProvenance.Deterministic, project.Configuration.Path, null,
                        "configuration:module-root", Confidence.Confirmed), supportingEvidence);
            }
        }

        var modules = candidates.Values.OrderBy(item => item.Key, StringComparer.Ordinal).ToArray();
        var ownerByPath = new Dictionary<string, ApplicationBoundary>(PathComparer());
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var owner = modules.Where(item => IsWithinPath(document.Path, item.RootPath))
                .OrderByDescending(item => SegmentCount(item.RootPath))
                .ThenByDescending(item => item.Origin == ModuleOrigin.Configuration)
                .ThenBy(item => item.RootPath, StringComparer.Ordinal)
                .ThenBy(item => item.Key, StringComparer.Ordinal)
                .FirstOrDefault() ?? deployable;
            ownerByPath.Add(document.Path, owner);
        }

        return new(deployable, modules, ownerByPath,
            diagnostics.OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static ApplicationBoundary Boundary(
        PhpProjectModel project,
        string root,
        string name,
        ModuleOrigin origin,
        Confidence confidence,
        EvidenceSeed evidence,
        IReadOnlyList<EvidenceSeed>? supportingEvidence = null)
    {
        var relative = project.RootPath.Length == 0 ? root : root[(project.RootPath.Length + 1)..];
        return new($"php:module:{project.ComposerPath}:{relative}", name, NodeKind.Module, root,
            origin, confidence, Resolution.Resolved, evidence, supportingEvidence ?? []);
    }

    private static string FriendlyName(string value)
    {
        var words = value.Split(['-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', words.Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
    }

    private static bool IsWithinPath(string path, string directory) =>
        directory.Length == 0 || path.StartsWith($"{directory}/", PathComparison());

    private static bool IsWithinOrEqual(string path, string directory) =>
        PathComparer().Equals(path, directory) || IsWithinPath(path, directory);

    private static int SegmentCount(string path) => path.Count(character => character == '/') + 1;

    private static string Combine(string root, string path) =>
        root.Length == 0 ? path : path.Length == 0 ? root : $"{root}/{path}";

    private static Diagnostic Diagnostic(string code, string message, string? subject, string key) =>
        new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}", code, "warning", message, subject);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private static StringComparer PathComparer() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static StringComparison PathComparison() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}
