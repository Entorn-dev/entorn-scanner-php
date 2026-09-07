using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Archie.Scanner.Php;

internal sealed class PhpRepositoryModelBuilder(PhpScannerLimits limits)
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public async Task<PhpRepositoryModel> BuildAsync(string repositoryRoot, CancellationToken cancellationToken)
    {
        var root = Path.GetFullPath(repositoryRoot);
        var diagnostics = new List<Diagnostic>();
        var inputBudget = new InputBudget(limits);
        var files = EnumerateInputs(root, inputBudget, diagnostics, cancellationToken);
        var paths = files.Select(item => item.Path).ToHashSet(PathComparer());
        var projects = new List<PhpProjectModel>();
        var documents = new List<PhpDocument>();
        var syntaxNodes = 0;
        var symbols = 0;
        var references = 0;
        var configuredModules = 0;
        using var syntax = new PhpSyntax();

        try
        {
            foreach (var composer in files.Where(item => Path.GetFileName(item.Path) == "composer.json"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var rootPath = NormalizeDirectory(Path.GetDirectoryName(composer.Path));
                var metadata = await ReadProjectAsync(rootPath, composer, files, paths, diagnostics, cancellationToken);
                if (metadata is null) continue;

                var projectDocuments = new List<PhpDocument>();
                foreach (var source in files.Where(item => IsSemanticSource(item, rootPath, metadata, files))
                             .DistinctBy(item => item.Path, PathComparer()).OrderBy(item => item.Path, StringComparer.Ordinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    inputBudget.Add(source, limits.MaxPhpFileBytes);
                    string text;
                    try
                    {
                        text = StrictUtf8.GetString(await File.ReadAllBytesAsync(source.FullPath, cancellationToken));
                    }
                    catch (DecoderFallbackException)
                    {
                        AddDiagnostic(diagnostics, "PHP_SOURCE_ENCODING_INVALID", "warning",
                            $"PHP source '{source.Path}' is not valid UTF-8 and was not interpreted.", metadata.Key, source.Path);
                        continue;
                    }

                    var parsed = syntax.ParseDocument(source.Path, text, limits, ref syntaxNodes, cancellationToken);
                    if (parsed.Validation.HasErrors)
                    {
                        AddDiagnostic(diagnostics, "PHP_SOURCE_MALFORMED", "warning",
                            $"PHP source '{source.Path}' contains parser recovery nodes and produced no source-derived facts.",
                            metadata.Key, source.Path);
                        continue;
                    }
                    projectDocuments.Add(parsed.Document!);
                    documents.Add(parsed.Document!);
                }

                symbols += projectDocuments.Sum(document =>
                    document.Classes.Sum(declaration => 1 + declaration.Methods.Count));
                if (symbols > limits.MaxSymbols)
                    throw new PhpWorkerLimitException("PHP_SYMBOL_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded symbol budget.");
                references += projectDocuments.Sum(document => document.Imports.Count +
                    document.Classes.Sum(declaration => declaration.BaseTypes.Count + declaration.Traits.Count));
                if (references > limits.MaxReferences)
                    throw new PhpWorkerLimitException("PHP_REFERENCE_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded static-reference budget.");
                var classes = IndexClasses(metadata.Key, metadata.Psr4Roots, projectDocuments, diagnostics);
                var typesByPath = classes.Values.GroupBy(item => item.Path, PathComparer())
                    .ToDictionary(item => item.Key,
                        item => (IReadOnlyList<PhpClassDeclaration>)item.OrderBy(type => type.FullyQualifiedName,
                            StringComparer.OrdinalIgnoreCase).ToArray(), PathComparer());
                PhpDiscoveryConfiguration? configuration = null;
                var configurationPath = Combine(rootPath, ".archie/php-discovery.json");
                var configurationFile = files.FirstOrDefault(item => PathComparer().Equals(item.Path, configurationPath));
                if (metadata.IsLaravel && configurationFile is not null)
                {
                    configuration = await PhpDiscoveryConfigurationReader.ReadAsync(
                        configurationFile, limits, diagnostics, cancellationToken);
                    configuredModules += configuration?.Modules.Count ?? 0;
                    if (configuredModules > limits.MaxConfiguredModules)
                        throw new PhpWorkerLimitException("PHP_CONFIGURED_MODULE_LIMIT_EXCEEDED",
                            "The PHP scanner exceeded its bounded configured-module budget.");
                }
                projects.Add(new(metadata.Key, metadata.Name, rootPath, composer.Path, metadata.IsLaravel,
                    metadata.Psr4Roots, metadata.Packages, projectDocuments,
                    new(classes, typesByPath), configuration));
            }

            return new(
                projects.OrderBy(item => item.ComposerPath, StringComparer.Ordinal).ToArray(),
                diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
        }
        catch
        {
            foreach (var document in documents) document.Dispose();
            throw;
        }
    }

    private async Task<ProjectMetadata?> ReadProjectAsync(
        string rootPath,
        SourceFile composer,
        IReadOnlyList<SourceFile> files,
        IReadOnlySet<string> paths,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(await File.ReadAllBytesAsync(composer.FullPath, cancellationToken),
                new() { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64 });
        }
        catch (JsonException)
        {
            AddDiagnostic(diagnostics, "PHP_COMPOSER_INVALID", "warning",
                $"Composer metadata '{composer.Path}' is not valid bounded JSON and was not interpreted.", null, composer.Path);
            return null;
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                AddDiagnostic(diagnostics, "PHP_COMPOSER_INVALID", "warning",
                    $"Composer metadata '{composer.Path}' does not have an object root and was not interpreted.", null, composer.Path);
                return null;
            }

            var key = $"php:composer-project:{composer.Path}";
            var requirements = ReadRequirements(document.RootElement);
            var lockPath = Combine(rootPath, "composer.lock");
            var lockFile = files.FirstOrDefault(item => PathComparer().Equals(item.Path, lockPath));
            var lockedPackages = lockFile is null
                ? []
                : await ReadLockedPackagesAsync(lockFile, key, diagnostics, cancellationToken);
            var packages = ResolvePackages(requirements.Production, lockedPackages, key, diagnostics);
            var directLaravel = requirements.Production.Count(item =>
                item.Name.Equals("laravel/framework", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(item.Version)) == 1;
            var lockedLaravel = packages.Count(item =>
                item.Name.Equals("laravel/framework", StringComparison.OrdinalIgnoreCase) &&
                item.Resolution == Resolution.Resolved && !string.IsNullOrWhiteSpace(item.LockedVersion)) == 1;
            var conventional = paths.Contains(Combine(rootPath, "artisan")) &&
                               paths.Contains(Combine(rootPath, "bootstrap/app.php")) &&
                               paths.Any(path => IsWithinPath(path, Combine(rootPath, "routes")) && path.EndsWith(".php", StringComparison.OrdinalIgnoreCase)) &&
                               paths.Any(path => IsWithinPath(path, Combine(rootPath, "app/Http")) && path.EndsWith(".php", StringComparison.OrdinalIgnoreCase));
            var name = ReadProjectName(document.RootElement, rootPath, composer.FullPath);
            var psr4Roots = ReadPsr4Roots(document.RootElement, rootPath);
            return new(key, name, directLaravel && lockedLaravel && conventional, psr4Roots, packages);
        }
    }

    private async Task<IReadOnlyList<LockedPackage>> ReadLockedPackagesAsync(
        SourceFile lockFile,
        string projectKey,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        try
        {
            using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(lockFile.FullPath, cancellationToken),
                new() { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return [];
            var result = new List<LockedPackage>();
            var count = 0;
            foreach (var propertyName in new[] { "packages", "packages-dev" })
            {
                if (!document.RootElement.TryGetProperty(propertyName, out var packages) || packages.ValueKind != JsonValueKind.Array)
                    continue;
                foreach (var package in packages.EnumerateArray())
                {
                    if (++count > limits.MaxComposerPackages)
                        throw new PhpWorkerLimitException("PHP_COMPOSER_PACKAGE_LIMIT_EXCEEDED",
                            "The PHP scanner exceeded its bounded Composer package budget.");
                    if (package.ValueKind != JsonValueKind.Object ||
                        !package.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String ||
                        !package.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String ||
                        string.IsNullOrWhiteSpace(name.GetString()) || string.IsNullOrWhiteSpace(version.GetString()))
                        continue;
                    result.Add(new(name.GetString()!, version.GetString()!));
                }
            }
            return result;
        }
        catch (JsonException)
        {
            AddDiagnostic(diagnostics, "PHP_COMPOSER_LOCK_INVALID", "warning",
                $"Composer lock metadata '{lockFile.Path}' is not valid bounded JSON and was not interpreted.",
                projectKey, lockFile.Path);
            return [];
        }
    }

    private IReadOnlyList<ComposerPackage> ResolvePackages(
        IReadOnlyList<Requirement> requirements,
        IReadOnlyList<LockedPackage> lockedPackages,
        string projectKey,
        ICollection<Diagnostic> diagnostics)
    {
        var result = new List<ComposerPackage>();
        foreach (var group in requirements.Where(item => !IsPlatformPackage(item.Name))
                     .GroupBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            var requested = group.Select(item => item.Version).Distinct(StringComparer.Ordinal).ToArray();
            var locked = lockedPackages.Where(item => item.Name.Equals(group.Key, StringComparison.OrdinalIgnoreCase)).ToArray();
            var resolution = group.Count() == 1 && requested.Length == 1 && locked.Length == 1
                ? Resolution.Resolved
                : group.Count() > 1 || requested.Length > 1 || locked.Length > 1 ? Resolution.Ambiguous : Resolution.Unresolved;
            result.Add(new(group.Key.ToLowerInvariant(), string.Join(" | ", requested.Order(StringComparer.Ordinal)),
                locked.Length == 1 ? locked[0].Version : null, resolution));
            if (resolution == Resolution.Ambiguous)
                AddDiagnostic(diagnostics, "PHP_COMPOSER_PACKAGE_AMBIGUOUS", "warning",
                    $"Direct Composer dependency '{group.Key}' has conflicting request or lock metadata and remains ambiguous.",
                    projectKey, $"{projectKey}:{group.Key}");
        }
        return result;
    }

    private IReadOnlyDictionary<string, PhpClassDeclaration> IndexClasses(
        string projectKey,
        IReadOnlyList<Psr4Root> roots,
        IReadOnlyList<PhpDocument> documents,
        ICollection<Diagnostic> diagnostics)
    {
        var classes = documents.SelectMany(item => item.Classes)
            .Where(declaration => roots.Any(root => MatchesPsr4(declaration, root)))
            .GroupBy(item => item.FullyQualifiedName, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, PhpClassDeclaration>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in classes.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            var declarations = group.OrderBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.Range.StartLine).ToArray();
            if (declarations.Length == 1)
            {
                result.Add(group.Key, declarations[0]);
                continue;
            }
            AddDiagnostic(diagnostics, "PHP_CLASS_AMBIGUOUS", "warning",
                $"PHP class '{group.Key}' has multiple PSR-4 declarations and was not resolved.",
                projectKey, $"{projectKey}:{group.Key}");
        }
        return result;
    }

    private static Requirements ReadRequirements(JsonElement root)
    {
        var production = ReadRequirementProperty(root, "require");
        var development = ReadRequirementProperty(root, "require-dev");
        return new(production, production.Concat(development).ToArray());
    }

    private static IReadOnlyList<Requirement> ReadRequirementProperty(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Object) return [];
        return value.EnumerateObject()
            .Where(item => item.Value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.Value.GetString()))
            .Select(item => new Requirement(item.Name, item.Value.GetString()!)).ToArray();
    }

    private static IReadOnlyList<Psr4Root> ReadPsr4Roots(JsonElement root, string projectRoot)
    {
        if (!root.TryGetProperty("autoload", out var autoload) || autoload.ValueKind != JsonValueKind.Object ||
            !autoload.TryGetProperty("psr-4", out var psr4) || psr4.ValueKind != JsonValueKind.Object)
            return [];
        var result = new List<Psr4Root>();
        foreach (var mapping in psr4.EnumerateObject())
        {
            var prefix = NormalizeNamespacePrefix(mapping.Name);
            if (prefix is null) continue;
            var values = mapping.Value.ValueKind == JsonValueKind.String
                ? new[] { mapping.Value.GetString() }
                : mapping.Value.ValueKind == JsonValueKind.Array
                    ? mapping.Value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()).ToArray()
                    : [];
            foreach (var value in values)
            {
                var path = NormalizePsr4Path(value);
                if (path is not null) result.Add(new(prefix, Combine(projectRoot, path)));
            }
        }
        return result.Distinct().OrderBy(item => item.NamespacePrefix, StringComparer.Ordinal)
            .ThenBy(item => item.Path, StringComparer.Ordinal).ToArray();
    }

    private static bool MatchesPsr4(PhpClassDeclaration declaration, Psr4Root root)
    {
        if (!declaration.FullyQualifiedName.StartsWith(root.NamespacePrefix, StringComparison.OrdinalIgnoreCase)) return false;
        var relativeClass = declaration.FullyQualifiedName[root.NamespacePrefix.Length..];
        if (relativeClass.Length == 0) return false;
        var expectedPath = Combine(root.Path, $"{relativeClass.Replace('\\', '/')}.php");
        return PathComparer().Equals(declaration.Path, expectedPath);
    }

    private static string ReadProjectName(JsonElement root, string rootPath, string composerFullPath)
    {
        if (root.TryGetProperty("name", out var property) && property.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(property.GetString()))
        {
            var packageName = property.GetString()!;
            return FriendlyName(packageName.Split('/').Last());
        }
        return FriendlyName(rootPath.Length == 0 ? Path.GetDirectoryName(composerFullPath) : rootPath);
    }

    private IReadOnlyList<SourceFile> EnumerateInputs(
        string root,
        InputBudget inputBudget,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        var result = new List<SourceFile>();
        var ignore = new RepositoryIgnore(limits.MaxInputFiles);
        var stack = new Stack<DirectoryInfo>();
        var rootDirectory = new DirectoryInfo(root);
        if ((rootDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new PhpWorkerLimitException("PHP_REPOSITORY_SYMLINK_REJECTED",
                "The PHP scanner does not scan a symbolic-link repository root.");
        stack.Push(rootDirectory);
        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = stack.Pop();
            var entries = directory.EnumerateFileSystemInfos().OrderBy(item => item.Name, StringComparer.Ordinal).ToArray();
            var ignoreFile = entries.OfType<FileInfo>().FirstOrDefault(item => item.Name == ".gitignore");
            if (ignoreFile is not null && (ignoreFile.Attributes & FileAttributes.ReparsePoint) == 0)
            {
                inputBudget.Add(ignoreFile, limits.MaxMetadataFileBytes);
                try
                {
                    ignore.Add(NormalizeDirectory(Path.GetDirectoryName(Relative(root, ignoreFile.FullName))),
                        StrictUtf8.GetString(File.ReadAllBytes(ignoreFile.FullName)));
                }
                catch (DecoderFallbackException)
                {
                    throw new PhpWorkerLimitException("PHP_GITIGNORE_ENCODING_INVALID",
                        "A repository .gitignore file is not valid UTF-8 and could not be interpreted safely.");
                }
            }

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = Relative(root, entry.FullName);
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    AddDiagnostic(diagnostics, "PHP_SYMLINK_SKIPPED", "warning",
                        "The PHP scanner does not follow symbolic links.", null, relative);
                    continue;
                }

                if (entry is DirectoryInfo child)
                {
                    if (child.Name is not (".git" or "bin" or "obj" or "node_modules" or "vendor") &&
                        !ignore.IsIgnored(relative, isDirectory: true))
                        stack.Push(child);
                    continue;
                }

                if (entry is not FileInfo file || file.Name == ".gitignore" || !IsRelevant(file, relative) ||
                    ignore.IsIgnored(relative, isDirectory: false))
                    continue;
                var fileLimit = IsDiscoveryConfiguration(relative)
                    ? limits.MaxDiscoveryConfigurationBytes
                    : file.Extension.Equals(".php", StringComparison.OrdinalIgnoreCase)
                        ? limits.MaxPhpFileBytes
                        : limits.MaxMetadataFileBytes;
                if (!file.Extension.Equals(".php", StringComparison.OrdinalIgnoreCase))
                    inputBudget.Add(file, fileLimit);
                result.Add(new(relative, file.FullName, file.Length));
            }
        }

        return result.OrderBy(item => item.Path, StringComparer.Ordinal).ToArray();
    }

    private void AddDiagnostic(
        ICollection<Diagnostic> diagnostics,
        string code,
        string severity,
        string message,
        string? subject,
        string key)
    {
        if (diagnostics.Count >= limits.MaxDiagnostics)
            throw new PhpWorkerLimitException("PHP_DIAGNOSTIC_LIMIT_EXCEEDED",
                "The PHP scanner exceeded its bounded diagnostic budget.");
        diagnostics.Add(new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}", code, severity, message, subject));
    }

    private static string? NormalizeNamespacePrefix(string value)
    {
        var prefix = value.Trim().TrimStart('\\');
        if (prefix.Length == 0) return string.Empty;
        prefix = prefix.TrimEnd('\\');
        if (prefix.Length == 0 || !prefix.Split('\\').All(IsIdentifier)) return null;
        return $"{prefix}\\";
    }

    private static string? NormalizePsr4Path(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || Path.IsPathRooted(value)) return null;
        var segments = value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or "..")) return null;
        return string.Join('/', segments);
    }

    private static bool IsIdentifier(string value) =>
        value.Length > 0 && (char.IsLetter(value[0]) || value[0] == '_' || value[0] >= '\u0080') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_' || character >= '\u0080');

    private static bool IsPlatformPackage(string name) =>
        name.Equals("php", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("ext-", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("lib-", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("composer-plugin-api", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("composer-runtime-api", StringComparison.OrdinalIgnoreCase);

    private static bool IsRelevant(FileInfo file, string relativePath) =>
        file.Extension.Equals(".php", StringComparison.OrdinalIgnoreCase) &&
        !file.Name.EndsWith(".blade.php", StringComparison.OrdinalIgnoreCase) ||
        file.Name is "composer.json" or "composer.lock" or "artisan" ||
        IsDiscoveryConfiguration(relativePath);

    private static bool IsDiscoveryConfiguration(string path) =>
        path.Equals(".archie/php-discovery.json", PathComparison()) ||
        path.EndsWith("/.archie/php-discovery.json", PathComparison());

    private static bool IsSemanticSource(
        SourceFile source,
        string projectRoot,
        ProjectMetadata metadata,
        IReadOnlyList<SourceFile> files) =>
        source.Path.EndsWith(".php", StringComparison.OrdinalIgnoreCase) &&
        IsOwnedBy(source.Path, projectRoot, files) &&
        (metadata.Psr4Roots.Any(root => IsWithinPath(source.Path, root.Path)) ||
         metadata.IsLaravel && IsWithinPath(source.Path, Combine(projectRoot, "routes")));

    private static bool IsOwnedBy(string sourcePath, string projectRoot, IReadOnlyList<SourceFile> files)
    {
        if (!IsWithinPath(sourcePath, projectRoot)) return false;
        var nearest = files.Where(item => Path.GetFileName(item.Path) == "composer.json")
            .Select(item => NormalizeDirectory(Path.GetDirectoryName(item.Path)))
            .Where(root => IsWithinPath(sourcePath, root))
            .OrderByDescending(root => root.Length)
            .FirstOrDefault();
        return PathComparer().Equals(nearest ?? string.Empty, projectRoot);
    }

    private static bool IsWithinPath(string path, string directory) =>
        directory.Length == 0 || path.StartsWith($"{directory}/", PathComparison());

    private static string Combine(string root, string path) => root.Length == 0 ? path : path.Length == 0 ? root : $"{root}/{path}";

    private static string NormalizeDirectory(string? directory) =>
        string.IsNullOrEmpty(directory) || directory == "." ? string.Empty : directory.Replace('\\', '/').Trim('/');

    private static string FriendlyName(string? path)
    {
        var value = Path.GetFileName(path?.Replace('/', Path.DirectorySeparatorChar).TrimEnd(Path.DirectorySeparatorChar)) ?? "PHP project";
        var words = value.Split(['-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', words.Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
    }

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private static StringComparer PathComparer() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static StringComparison PathComparison() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private sealed class InputBudget(PhpScannerLimits limits)
    {
        private long bytes;
        private int files;

        public void Add(FileInfo file, long fileLimit) => Add(file.Name, file.Length, fileLimit);

        public void Add(SourceFile file, long fileLimit) => Add(file.Path, file.Bytes, fileLimit);

        private void Add(string path, long length, long fileLimit)
        {
            if (length > fileLimit)
                throw new PhpWorkerLimitException("PHP_INPUT_FILE_LIMIT_EXCEEDED",
                    $"Eligible PHP scanner input '{path}' exceeded its bounded per-file byte budget ({length} bytes; limit {fileLimit}).");
            bytes += length;
            if (++files > limits.MaxInputFiles || bytes > limits.MaxInputBytes)
                throw new PhpWorkerLimitException("PHP_INPUT_LIMIT_EXCEEDED",
                    $"Eligible PHP scanner input '{path}' exceeded the aggregate input budget " +
                    $"({files} files/{bytes} bytes; limits {limits.MaxInputFiles} files/{limits.MaxInputBytes} bytes).");
        }
    }

    private sealed class RepositoryIgnore(int maxRules)
    {
        private readonly List<IgnoreRule> rules = [];

        public void Add(string baseDirectory, string contents)
        {
            foreach (var line in contents.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
            {
                var rule = IgnoreRule.TryCreate(baseDirectory, line);
                if (rule is null) continue;
                if (rules.Count >= maxRules)
                    throw new PhpWorkerLimitException("PHP_GITIGNORE_RULE_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded repository ignore-rule budget.");
                rules.Add(rule);
            }
        }

        public bool IsIgnored(string path, bool isDirectory)
        {
            var ignored = false;
            foreach (var rule in rules)
            {
                if (rule.Matches(path, isDirectory)) ignored = !rule.Negated;
            }
            return ignored;
        }
    }

    private sealed record IgnoreRule(string BaseDirectory, Regex Pattern, bool Negated, bool DirectoryOnly)
    {
        public static IgnoreRule? TryCreate(string baseDirectory, string value)
        {
            var line = TrimUnescapedTrailingSpaces(value.TrimEnd('\r'));
            if (line.Length == 0 || line[0] == '#') return null;

            var negated = line[0] == '!';
            if (negated) line = line[1..];
            else if (line.StartsWith("\\!", StringComparison.Ordinal) || line.StartsWith("\\#", StringComparison.Ordinal))
                line = line[1..];
            if (line.Length == 0) return null;

            var directoryOnly = line.EndsWith('/') && !IsEscaped(line, line.Length - 1);
            if (directoryOnly) line = line[..^1];
            var anchored = line.StartsWith('/') || line.Contains('/');
            if (line.StartsWith('/')) line = line[1..];
            if (line.Length == 0) return null;

            var expression = anchored
                ? $"^{Glob(line)}$"
                : $"(?:^|/){Glob(line)}$";
            var options = RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;
            if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()) options |= RegexOptions.IgnoreCase;
            try
            {
                return new(baseDirectory, new(expression, options, TimeSpan.FromMilliseconds(100)), negated, directoryOnly);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        public bool Matches(string path, bool isDirectory)
        {
            if (DirectoryOnly && !isDirectory) return false;
            if (BaseDirectory.Length > 0)
            {
                if (!path.StartsWith($"{BaseDirectory}/", PathComparison())) return false;
                path = path[(BaseDirectory.Length + 1)..];
            }
            return Pattern.IsMatch(path);
        }

        private static string Glob(string pattern)
        {
            var result = new StringBuilder();
            for (var index = 0; index < pattern.Length; index++)
            {
                var character = pattern[index];
                if (character == '\\' && index + 1 < pattern.Length)
                {
                    result.Append(Regex.Escape(pattern[++index].ToString()));
                    continue;
                }
                if (character == '*')
                {
                    var doubleStar = index + 1 < pattern.Length && pattern[index + 1] == '*';
                    if (!doubleStar)
                    {
                        result.Append("[^/]*");
                        continue;
                    }
                    while (index + 1 < pattern.Length && pattern[index + 1] == '*') index++;
                    if (index + 1 < pattern.Length && pattern[index + 1] == '/')
                    {
                        index++;
                        result.Append("(?:.*/)?");
                    }
                    else result.Append(".*");
                    continue;
                }
                if (character == '?')
                {
                    result.Append("[^/]");
                    continue;
                }
                if (character == '[')
                {
                    var end = pattern.IndexOf(']', index + 1);
                    if (end > index + 1)
                    {
                        var contents = pattern[(index + 1)..end];
                        result.Append('[');
                        if (contents[0] == '!') result.Append('^').Append(contents.AsSpan(1));
                        else result.Append(contents);
                        result.Append(']');
                        index = end;
                        continue;
                    }
                }
                result.Append(Regex.Escape(character.ToString()));
            }
            return result.ToString();
        }

        private static string TrimUnescapedTrailingSpaces(string value)
        {
            var length = value.Length;
            while (length > 0 && value[length - 1] == ' ' && !IsEscaped(value, length - 1)) length--;
            return value[..length];
        }

        private static bool IsEscaped(string value, int index)
        {
            var slashes = 0;
            while (--index >= 0 && value[index] == '\\') slashes++;
            return slashes % 2 == 1;
        }
    }

    private sealed record ProjectMetadata(
        string Key,
        string Name,
        bool IsLaravel,
        IReadOnlyList<Psr4Root> Psr4Roots,
        IReadOnlyList<ComposerPackage> Packages);

    private sealed record Requirement(string Name, string Version);
    private sealed record Requirements(IReadOnlyList<Requirement> Production, IReadOnlyList<Requirement> All);
    private sealed record LockedPackage(string Name, string Version);
}
