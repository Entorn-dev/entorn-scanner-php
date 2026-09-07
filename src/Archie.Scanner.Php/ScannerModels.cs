namespace Archie.Scanner.Php;

public sealed record PhpScannerLimits(
    int MaxInputFiles = 20_000,
    long MaxInputBytes = 64 * 1024 * 1024,
    long MaxPhpFileBytes = 2 * 1024 * 1024,
    long MaxMetadataFileBytes = 8 * 1024 * 1024,
    int MaxSyntaxNodesPerFile = 250_000,
    int MaxSyntaxNodes = 4 * 1024 * 1024,
    int MaxSyntaxDepth = 256,
    int MaxComposerPackages = 10_000,
    int MaxDiagnostics = 10_000,
    long MaxDiscoveryConfigurationBytes = 256 * 1024,
    int MaxConfiguredModules = 256,
    long MaxSnapshotFileBytes = 4 * 1024 * 1024,
    int MaxSnapshotJsonDepth = 16,
    int MaxSnapshotRecordsPerFile = 10_000,
    int MaxSnapshotCollectionItems = 256,
    int MaxSnapshotStringLength = 4_096,
    int MaxSymbols = 250_000,
    int MaxReferences = 1_000_000,
    int MaxDetections = 100_000);

public sealed record PhpScanResult(
    IReadOnlyList<Observation> Observations,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public IReadOnlyList<SourceOwnershipClaim> SourceOwnership { get; init; } = [];
    public bool Succeeded => Diagnostics.All(item => item.Severity != "error");
}

internal sealed record SourceFile(string Path, string FullPath, long Bytes);

internal sealed record ComposerPackage(
    string Name,
    string RequestedVersion,
    string? LockedVersion,
    Resolution Resolution);

internal sealed record Psr4Root(string NamespacePrefix, string Path);

internal enum PhpTypeKind
{
    Class,
    Interface,
    Trait,
    Enum
}

internal sealed record PhpClassDeclaration(
    PhpTypeKind Kind,
    string FullyQualifiedName,
    string Path,
    SourceRange Range,
    IReadOnlyList<string> BaseTypes,
    IReadOnlySet<string> Methods,
    IReadOnlySet<string> Traits);

internal sealed record PhpApplicationIndex(
    IReadOnlyDictionary<string, PhpClassDeclaration> Types,
    IReadOnlyDictionary<string, IReadOnlyList<PhpClassDeclaration>> TypesByPath);

internal sealed record ConfiguredModule(string Path, string? Name);

internal sealed record PhpDiscoveryConfiguration(
    string Path,
    IReadOnlyList<ConfiguredModule> Modules);

internal sealed record PhpProjectModel(
    string Key,
    string Name,
    string RootPath,
    string ComposerPath,
    bool IsLaravel,
    IReadOnlyList<Psr4Root> Psr4Roots,
    IReadOnlyList<ComposerPackage> Packages,
    IReadOnlyList<PhpDocument> Documents,
    PhpApplicationIndex Index,
    PhpDiscoveryConfiguration? Configuration)
{
    public IReadOnlyDictionary<string, PhpClassDeclaration> Classes => Index.Types;
}

internal static class PhpTypeRelations
{
    public static bool IsAssignableTo(PhpProjectModel project, string typeName, string targetType)
    {
        var pending = new Stack<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        pending.Push(typeName);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (!visited.Add(current)) continue;
            if (current.Equals(targetType, StringComparison.OrdinalIgnoreCase)) return true;
            if (!project.Classes.TryGetValue(current, out var declaration)) continue;
            foreach (var related in declaration.BaseTypes.Concat(declaration.Traits)) pending.Push(related);
        }
        return false;
    }
}

internal sealed class PhpRepositoryModel(
    IReadOnlyList<PhpProjectModel> projects,
    IReadOnlyList<Diagnostic> diagnostics) : IDisposable
{
    public IReadOnlyList<PhpProjectModel> Projects { get; } = projects;
    public IReadOnlyList<Diagnostic> Diagnostics { get; } = diagnostics;

    public void Dispose()
    {
        foreach (var document in Projects.SelectMany(item => item.Documents)) document.Dispose();
    }
}

internal sealed record LaravelEndpointDetection(
    string Method,
    string Template,
    string? Domain,
    string? Name,
    string? Controller,
    string? Action,
    string Path,
    SourceRange Range,
    string Rule,
    Confidence Confidence,
    Resolution Resolution);

internal sealed record LaravelScanResult(
    IReadOnlyList<LaravelEndpointDetection> Endpoints,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public IReadOnlyList<LaravelHttpDetection> HttpCalls { get; init; } = [];
    public IReadOnlyList<LaravelJobDispatchDetection> JobDispatches { get; init; } = [];
    public IReadOnlyList<LaravelEventPublicationDetection> EventPublications { get; init; } = [];
    public IReadOnlyList<LaravelEventSubscriptionDetection> EventSubscriptions { get; init; } = [];
    public IReadOnlyList<LaravelScheduleDetection> Schedules { get; init; } = [];
    public IReadOnlyList<LaravelEloquentModelDetection> EloquentModels { get; init; } = [];
    public IReadOnlyList<LaravelEloquentRelationDetection> EloquentRelations { get; init; } = [];
}

internal sealed record LaravelHttpDetection(
    string Origin,
    string Scheme,
    string Host,
    int? Port,
    string Path,
    SourceRange Range,
    string Rule);

internal sealed record LaravelJobDispatchDetection(
    string JobType,
    string JobPath,
    string Path,
    SourceRange Range,
    string Rule);

internal sealed record LaravelEventPublicationDetection(
    string ChannelKey,
    string ChannelName,
    string? EventType,
    string Path,
    SourceRange Range,
    string Rule);

internal sealed record LaravelEventSubscriptionDetection(
    string ChannelKey,
    string ChannelName,
    string? EventType,
    string ListenerType,
    string ListenerMethod,
    bool Queued,
    string Path,
    SourceRange Range,
    string Rule);

internal enum LaravelScheduleTargetKind
{
    Command,
    Job,
    Callback,
    Closure
}

internal sealed record LaravelScheduleCadence(
    string Kind,
    string? Expression,
    string? Frequency,
    int? IntervalSeconds,
    string? Timezone);

internal sealed record LaravelScheduleDetection(
    LaravelScheduleTargetKind TargetKind,
    string TargetKey,
    string TargetName,
    string? TargetType,
    string? TargetMethod,
    LaravelScheduleCadence Cadence,
    string Path,
    SourceRange Range,
    string Rule);

internal sealed record LaravelEloquentModelDetection(
    string ModelType,
    string Path,
    SourceRange Range,
    string Connection,
    bool IsDefaultConnection,
    Confidence Confidence,
    string Rule);

internal sealed record LaravelEloquentRelationDetection(
    string ModelType,
    string RelatedModelType,
    string Relation,
    string Path,
    SourceRange Range,
    string Rule);

internal enum ModuleOrigin
{
    Convention,
    Configuration,
    NestedComposer
}

internal sealed record EvidenceSeed(
    EvidenceProvenance Provenance,
    string Path,
    SourceRange? Range,
    string Rule,
    Confidence Confidence);

internal sealed record ApplicationBoundary(
    string Key,
    string Name,
    NodeKind Kind,
    string RootPath,
    ModuleOrigin? Origin,
    Confidence Confidence,
    Resolution Resolution,
    EvidenceSeed Evidence,
    IReadOnlyList<EvidenceSeed> SupportingEvidence);

internal sealed record BoundaryDiscoveryResult(
    ApplicationBoundary Deployable,
    IReadOnlyList<ApplicationBoundary> Modules,
    IReadOnlyDictionary<string, ApplicationBoundary> OwnerByPath,
    IReadOnlyList<Diagnostic> Diagnostics);

internal sealed record AssemblyResult(
    IReadOnlyList<Observation> Observations,
    IReadOnlyList<SourceOwnershipClaim> SourceOwnership,
    IReadOnlyList<Diagnostic> Diagnostics);

internal sealed class PhpWorkerLimitException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
