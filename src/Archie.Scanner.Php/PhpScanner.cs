using System.Security.Cryptography;
using System.Text;

namespace Archie.Scanner.Php;

public sealed class PhpScanner(PhpScannerLimits? limits = null)
{
    private readonly PhpScannerLimits limits = limits ?? new();

    public async Task<PhpScanResult> ScanAsync(string repositoryRoot, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(repositoryRoot))
            return new([], [Diagnostic("PHP_REPOSITORY_UNAVAILABLE", "error",
                "The requested repository directory does not exist.", null, "repository")]);

        try
        {
            using var repository = await new PhpRepositoryModelBuilder(limits).BuildAsync(repositoryRoot, cancellationToken);
            var boundaries = new Dictionary<string, BoundaryDiscoveryResult>(StringComparer.Ordinal);
            var laravelScans = new Dictionary<string, LaravelScanResult>(StringComparer.Ordinal);
            var recognitionProjects = new Dictionary<string, PhpProjectModel>(StringComparer.Ordinal);
            long detections = 0;
            foreach (var project in repository.Projects.Where(item => item.IsLaravel))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var recognitionProject = BuildRecognitionProject(project, repository.Projects);
                recognitionProjects.Add(project.Key, recognitionProject);
                var boundary = LaravelBoundaryDiscovery.Discover(project, limits, cancellationToken);
                boundaries.Add(project.Key, AddNestedProjectOwners(boundary, project, repository.Projects));
                var routeScan = LaravelRouteRecognizer.Scan(recognitionProject, cancellationToken);
                var httpScan = LaravelHttpRecognizer.Scan(recognitionProject, cancellationToken);
                var messagingScan = LaravelMessagingRecognizer.ScanJobs(recognitionProject, cancellationToken);
                var eventScan = LaravelMessagingRecognizer.ScanEvents(recognitionProject, cancellationToken);
                var scheduleScan = LaravelScheduleRecognizer.Scan(recognitionProject, cancellationToken);
                var eloquentScan = LaravelEloquentRecognizer.Scan(recognitionProject, cancellationToken);
                var scan = routeScan with
                {
                    HttpCalls = httpScan.Detections,
                    JobDispatches = messagingScan.JobDispatches,
                    EventPublications = eventScan.Publications,
                    EventSubscriptions = eventScan.Subscriptions,
                    Schedules = scheduleScan.Detections,
                    EloquentModels = eloquentScan.Models,
                    EloquentRelations = eloquentScan.Relations,
                    Diagnostics = routeScan.Diagnostics.Concat(httpScan.Diagnostics).Concat(messagingScan.Diagnostics)
                        .Concat(eventScan.Diagnostics).Concat(scheduleScan.Diagnostics).Concat(eloquentScan.Diagnostics)
                        .DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray()
                };
                detections += scan.Endpoints.Count + scan.HttpCalls.Count + scan.JobDispatches.Count +
                    scan.EventPublications.Count + scan.EventSubscriptions.Count + scan.Schedules.Count +
                    scan.EloquentModels.Count + scan.EloquentRelations.Count;
                if (detections > limits.MaxDetections)
                    throw new PhpWorkerLimitException("PHP_DETECTION_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded detection budget.");
                laravelScans.Add(project.Key, scan);
            }

            var assembly = new ObservationAssembler().Assemble(
                repository, boundaries, recognitionProjects, laravelScans, cancellationToken);
            var diagnostics = repository.Diagnostics.Concat(assembly.Diagnostics)
                .DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray();
            if (diagnostics.Length > limits.MaxDiagnostics)
                throw new PhpWorkerLimitException("PHP_DIAGNOSTIC_LIMIT_EXCEEDED",
                    "The PHP scanner exceeded its bounded diagnostic budget.");
            return new(assembly.Observations, diagnostics) { SourceOwnership = assembly.SourceOwnership };
        }
        catch (PhpWorkerLimitException exception)
        {
            return new([], [Diagnostic(exception.Code, "error", exception.Message, null, exception.Code)]);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new([], [Diagnostic("PHP_REPOSITORY_READ_FAILED", "error",
                "The PHP scanner could not read the bounded repository inputs.", null, exception.GetType().Name)]);
        }
    }

    private static Diagnostic Diagnostic(string code, string severity, string message, string? subject, string key) =>
        new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}", code, severity, message, subject);

    private static PhpProjectModel BuildRecognitionProject(
        PhpProjectModel laravelProject,
        IReadOnlyList<PhpProjectModel> projects)
    {
        var members = projects.Where(candidate => ReferenceEquals(candidate, laravelProject) ||
                !candidate.IsLaravel && candidate.Classes.Count > 0 &&
                ReferenceEquals(NearestLaravelProject(candidate, projects), laravelProject))
            .OrderBy(candidate => candidate.ComposerPath, StringComparer.Ordinal).ToArray();
        var types = members.SelectMany(candidate => candidate.Index.Types.Values)
            .GroupBy(declaration => declaration.FullyQualifiedName, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);
        var typesByPath = types.Values.GroupBy(declaration => declaration.Path, PathComparer())
            .ToDictionary(group => group.Key,
                group => (IReadOnlyList<PhpClassDeclaration>)group.OrderBy(declaration => declaration.FullyQualifiedName,
                    StringComparer.OrdinalIgnoreCase).ToArray(), PathComparer());
        return laravelProject with
        {
            Psr4Roots = members.SelectMany(candidate => candidate.Psr4Roots).Distinct().ToArray(),
            Packages = members.SelectMany(candidate => candidate.Packages).Distinct().ToArray(),
            Documents = members.SelectMany(candidate => candidate.Documents)
                .OrderBy(document => document.Path, StringComparer.Ordinal).ToArray(),
            Index = new(types, typesByPath)
        };
    }

    private static BoundaryDiscoveryResult AddNestedProjectOwners(
        BoundaryDiscoveryResult boundary,
        PhpProjectModel laravelProject,
        IReadOnlyList<PhpProjectModel> projects)
    {
        var owners = boundary.OwnerByPath.ToDictionary(item => item.Key, item => item.Value, PathComparer());
        foreach (var project in projects.Where(candidate => !candidate.IsLaravel && candidate.Classes.Count > 0 &&
                     ReferenceEquals(NearestLaravelProject(candidate, projects), laravelProject)))
        {
            var owner = new ApplicationBoundary(project.Key, project.Name, NodeKind.Module, project.RootPath, null,
                Confidence.Confirmed, Resolution.Resolved,
                new(EvidenceProvenance.Deterministic, project.ComposerPath, null,
                    "composer:nested-production-module", Confidence.Confirmed), []);
            foreach (var document in project.Documents) owners[document.Path] = owner;
        }
        return boundary with { OwnerByPath = owners };
    }

    private static PhpProjectModel? NearestLaravelProject(
        PhpProjectModel project,
        IReadOnlyList<PhpProjectModel> projects) =>
        projects.Where(candidate => candidate.IsLaravel && IsWithinPath(project.ComposerPath, candidate.RootPath))
            .OrderByDescending(candidate => candidate.RootPath.Length).FirstOrDefault();

    private static bool IsWithinPath(string path, string directory) =>
        directory.Length == 0 || path.StartsWith($"{directory}/", PathComparison());

    private static StringComparer PathComparer() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static StringComparison PathComparison() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];
}
