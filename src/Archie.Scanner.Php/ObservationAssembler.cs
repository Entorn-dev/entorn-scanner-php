using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Archie.Scanner.Php;

internal sealed class ObservationAssembler
{
    private const string ScannerId = "archie.php";
    private const string ScannerVersion = "2.0.0";

    public AssemblyResult Assemble(
        PhpRepositoryModel repository,
        IReadOnlyDictionary<string, BoundaryDiscoveryResult> boundaries,
        IReadOnlyDictionary<string, PhpProjectModel> recognitionProjects,
        IReadOnlyDictionary<string, LaravelScanResult> laravelScans,
        CancellationToken cancellationToken)
    {
        var observations = new List<Observation>();
        var ownership = new List<SourceOwnershipClaim>();
        var diagnostics = new List<Diagnostic>();
        var laravelProjects = repository.Projects.Where(item => item.IsLaravel).ToArray();

        foreach (var project in repository.Projects.OrderBy(item => item.ComposerPath, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var parentProject = repository.Projects.Where(parent => !ReferenceEquals(parent, project) &&
                    IsWithinPath(project.ComposerPath, parent.RootPath))
                .OrderByDescending(parent => parent.RootPath.Length).FirstOrDefault();
            var parentLaravel = laravelProjects.Where(parent => !ReferenceEquals(parent, project) &&
                    IsWithinPath(project.ComposerPath, parent.RootPath))
                .OrderByDescending(parent => parent.RootPath.Length).FirstOrDefault();
            EntityCandidate? architectureOwner;
            if (project.IsLaravel)
            {
                var discovery = boundaries[project.Key];
                diagnostics.AddRange(discovery.Diagnostics);
                architectureOwner = BoundaryCandidate(discovery.Deployable);
                foreach (var evidence in Evidence(discovery.Deployable))
                    observations.Add(Entity($"laravel:{project.ComposerPath}", architectureOwner, evidence));
                foreach (var module in discovery.Modules)
                {
                    var candidate = BoundaryCandidate(module);
                    foreach (var evidence in Evidence(module))
                    {
                        observations.Add(Entity($"module:{project.ComposerPath}:{module.RootPath}", candidate, evidence));
                        observations.Add(Relationship($"laravel-module:{project.ComposerPath}:{module.RootPath}",
                            EdgeKind.Contains, architectureOwner, candidate, evidence,
                            Properties(("ownership", module.Origin == ModuleOrigin.Configuration
                                ? "configured-module" : "conventional-module"), ("label", $"contains {module.Name}"))));
                    }
                }
            }
            else if (parentProject is not null)
            {
                if (project.Classes.Count == 0) continue;
                architectureOwner = ModuleCandidate(project);
                var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, project.ComposerPath, null,
                    "composer:nested-production-module", Confidence.Confirmed);
                observations.Add(Entity($"project:{project.ComposerPath}", architectureOwner, seed));
                if (parentLaravel is not null)
                {
                    var parent = BoundaryCandidate(boundaries[parentLaravel.Key].Deployable);
                    observations.Add(Relationship($"laravel-nested-module:{parentLaravel.ComposerPath}:{project.ComposerPath}",
                        EdgeKind.Contains, parent, architectureOwner, seed,
                        Properties(("ownership", "nested-composer-production"),
                            ("label", $"contains {architectureOwner.Name}"))));
                }
            }
            else
            {
                architectureOwner = ModuleCandidate(project);
                observations.Add(Entity($"project:{project.ComposerPath}", architectureOwner,
                    new(EvidenceProvenance.Deterministic, project.ComposerPath, null,
                        "composer:project-declaration", Confidence.Confirmed)));
            }

            foreach (var package in project.Packages)
            {
                var component = PackageCandidate(package);
                var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, project.ComposerPath, null,
                    "composer:direct-package-requirement", Confidence.Confirmed);
                observations.Add(Entity($"package:{project.ComposerPath}:{package.Name}", component, seed));
                observations.Add(Relationship($"package-dependency:{project.ComposerPath}:{package.Name}",
                    EdgeKind.DependsOn, architectureOwner, component, seed,
                    Properties(("package", package.Name), ("requestedVersion", package.RequestedVersion),
                        ("lockedVersion", package.LockedVersion), ("label", $"depends on {package.Name}"))));
            }

            AddOwnership(project, parentLaravel, boundaries, ownership);
            if (!project.IsLaravel || !laravelScans.TryGetValue(project.Key, out var scan)) continue;
            var recognitionProject = recognitionProjects[project.Key];
            diagnostics.AddRange(scan.Diagnostics);
            AddEndpoints(recognitionProject, boundaries[project.Key], scan.Endpoints, observations, diagnostics);
            AddHttpCalls(recognitionProject, boundaries[project.Key], scan.HttpCalls, observations);
            AddJobDispatches(recognitionProject, boundaries[project.Key], scan.JobDispatches, observations);
            AddEventPublications(recognitionProject, boundaries[project.Key], scan.EventPublications, observations);
            AddEventSubscriptions(recognitionProject, boundaries[project.Key], scan.EventSubscriptions, observations);
            AddSchedules(recognitionProject, boundaries[project.Key], scan.Schedules, observations);
            AddEloquent(recognitionProject, boundaries[project.Key], scan.EloquentModels, scan.EloquentRelations, observations);
        }

        return new(
            observations.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray(),
            ownership.DistinctBy(item => (item.Path, item.OwnerCandidateKey, item.OwnershipKind))
                .OrderBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.OwnerCandidateKey, StringComparer.Ordinal).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static void AddOwnership(
        PhpProjectModel project,
        PhpProjectModel? parentLaravel,
        IReadOnlyDictionary<string, BoundaryDiscoveryResult> boundaries,
        ICollection<SourceOwnershipClaim> ownership)
    {
        foreach (var document in project.Documents)
        {
            var projectRule = project.Index.TypesByPath.ContainsKey(document.Path)
                ? "composer:psr-4-class-ownership"
                : "composer:production-source-ownership";
            ownership.Add(new(ScannerId, ScannerVersion, document.Path, project.Key,
                SourceOwnershipKind.Project, Confidence.Confirmed, Resolution.Resolved,
                projectRule));
            if (project.IsLaravel)
            {
                var discovery = boundaries[project.Key];
                var owner = discovery.OwnerByPath.GetValueOrDefault(document.Path, discovery.Deployable);
                ownership.Add(new(ScannerId, ScannerVersion, document.Path, owner.Key,
                    owner.Kind == NodeKind.Module ? SourceOwnershipKind.Module : SourceOwnershipKind.Deployable,
                    owner.Confidence, owner.Resolution, owner.Evidence.Rule));
            }
            else if (parentLaravel is not null && project.Classes.Count > 0)
            {
                ownership.Add(new(ScannerId, ScannerVersion, document.Path, project.Key,
                    SourceOwnershipKind.Module, Confidence.Confirmed, Resolution.Resolved,
                    "composer:nested-production-module"));
            }
        }
    }

    private static void AddEndpoints(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelEndpointDetection> endpoints,
        ICollection<Observation> observations,
        ICollection<Diagnostic> diagnostics)
    {
        var deployable = BoundaryCandidate(boundaries.Deployable);
        foreach (var group in endpoints.GroupBy(item =>
                     $"{item.Method}\n{item.Domain ?? string.Empty}\n{item.Template}", StringComparer.Ordinal))
        {
            var detections = group.OrderBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.Range.StartLine).ThenBy(item => item.Range.StartColumn).ToArray();
            var targets = detections.Select(TargetKey).Distinct(StringComparer.Ordinal).ToArray();
            var ambiguous = targets.Length > 1;
            if (ambiguous)
                diagnostics.Add(Diagnostic("PHP_LARAVEL_ENDPOINT_AMBIGUOUS",
                    $"Laravel application '{project.ComposerPath}' declares {detections.Length} endpoints for {detections[0].Method} {detections[0].Template}; they remain separate and ambiguous.",
                    project.Key, $"{project.ComposerPath}:{group.Key}"));
            foreach (var detection in detections)
            {
                var endpoint = EndpointCandidate(project, detection, ambiguous);
                var suffix = ambiguous
                    ? $":target:{Stable(TargetKey(detection))}"
                    : string.Empty;
                var identity = EndpointIdentity(detection);
                var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                    detection.Rule, detection.Confidence);
                var controllerPath = detection.Controller is null
                    ? null
                    : project.Classes.GetValueOrDefault(detection.Controller)?.Path;
                var owner = controllerPath is not null
                    ? boundaries.OwnerByPath.GetValueOrDefault(controllerPath, boundaries.Deployable)
                    : boundaries.OwnerByPath.GetValueOrDefault(detection.Path, boundaries.Deployable);
                var ownerCandidate = BoundaryCandidate(owner);
                observations.Add(Entity(
                    $"endpoint:{project.ComposerPath}:{identity}{suffix}", endpoint, seed));
                observations.Add(Relationship(
                    $"owner-endpoint:{owner.Key}:{identity}{suffix}",
                    EdgeKind.Contains, ownerCandidate, endpoint, seed,
                    Properties(("ownership", "laravel-endpoint"),
                        ("label", $"owns {detection.Method} {detection.Template}"))));
                observations.Add(Relationship(
                    $"laravel-endpoint:{project.ComposerPath}:{identity}{suffix}",
                    EdgeKind.Exposes, deployable, endpoint, seed,
                    Properties(("httpMethod", detection.Method), ("routeTemplate", detection.Template),
                        ("domain", detection.Domain), ("routeName", detection.Name),
                        ("controller", detection.Controller), ("action", detection.Action),
                        ("ownership", "laravel-application-endpoint"),
                        ("label", $"exposes {detection.Method} {detection.Template}"))));
            }
        }
    }

    private static void AddHttpCalls(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelHttpDetection> detections,
        ICollection<Observation> observations)
    {
        foreach (var detection in detections)
        {
            var service = Candidate($"php:external-service:{detection.Origin}", NodeKind.ExternalService,
                detection.Origin, Resolution.Resolved,
                Properties(("origin", detection.Origin), ("scheme", detection.Scheme),
                    ("host", detection.Host), ("port", detection.Port)));
            var owner = boundaries.OwnerByPath.GetValueOrDefault(detection.Path, boundaries.Deployable);
            var ownerCandidate = BoundaryCandidate(owner);
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                detection.Rule, Confidence.Confirmed);
            observations.Add(Entity($"external-service:{detection.Origin}", service, seed));
            observations.Add(Relationship($"http-call:{owner.Key}:{detection.Origin}",
                EdgeKind.Calls, ownerCandidate, service, seed,
                Properties(("origin", detection.Origin), ("ownership", "laravel-http-client"),
                    ("label", $"calls {detection.Origin}"))));
        }
    }

    private static void AddJobDispatches(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelJobDispatchDetection> detections,
        ICollection<Observation> observations)
    {
        foreach (var detection in detections)
        {
            var channel = Candidate($"php:laravel-job:{project.ComposerPath}:{detection.JobType}",
                NodeKind.MessageChannel, detection.JobType, Resolution.Resolved,
                Properties(("messageType", "job"), ("contract", detection.JobType), ("queued", true)));
            var contract = Candidate($"php:type:{project.ComposerPath}:{detection.JobType}",
                NodeKind.Component, detection.JobType.Split('\\').Last(), Resolution.Resolved,
                Properties(("language", "php"), ("type", detection.JobType), ("role", "queued-job-contract")));
            var owner = boundaries.OwnerByPath.GetValueOrDefault(detection.Path, boundaries.Deployable);
            var ownerCandidate = BoundaryCandidate(owner);
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                detection.Rule, Confidence.Confirmed);
            observations.Add(Entity($"job-channel:{project.ComposerPath}:{detection.JobType}", channel, seed));
            observations.Add(Entity($"job-contract:{project.ComposerPath}:{detection.JobType}", contract, seed));
            observations.Add(Relationship($"job-publish:{owner.Key}:{detection.JobType}",
                EdgeKind.Publishes, ownerCandidate, channel, seed,
                Properties(("messageType", "job"), ("queued", true),
                    ("label", $"publishes {detection.JobType.Split('\\').Last()}"))));
            observations.Add(Relationship($"job-contract-use:{owner.Key}:{detection.JobType}",
                EdgeKind.UsesContract, ownerCandidate, contract, seed,
                Properties(("contract", detection.JobType),
                    ("label", $"uses {detection.JobType.Split('\\').Last()} contract"))));
        }
    }

    private static void AddEventPublications(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelEventPublicationDetection> detections,
        ICollection<Observation> observations)
    {
        foreach (var detection in detections)
        {
            var channel = EventChannelCandidate(project, detection.ChannelKey, detection.ChannelName,
                detection.EventType);
            var owner = boundaries.OwnerByPath.GetValueOrDefault(detection.Path, boundaries.Deployable);
            var ownerCandidate = BoundaryCandidate(owner);
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                detection.Rule, Confidence.Confirmed);
            observations.Add(Entity($"event-channel:{project.ComposerPath}:{detection.ChannelKey}", channel, seed));
            observations.Add(Relationship($"event-publish:{owner.Key}:{detection.ChannelKey}",
                EdgeKind.Publishes, ownerCandidate, channel, seed,
                Properties(("messageType", "event"), ("event", detection.ChannelName),
                    ("label", $"publishes {detection.ChannelName.Split('\\').Last()}"))));
            if (detection.EventType is not { } eventType) continue;
            var contract = EventContractCandidate(project, eventType);
            observations.Add(Entity($"event-contract:{project.ComposerPath}:{eventType}", contract, seed));
            observations.Add(Relationship($"event-contract-use:{owner.Key}:{eventType}",
                EdgeKind.UsesContract, ownerCandidate, contract, seed,
                Properties(("contract", eventType),
                    ("label", $"uses {eventType.Split('\\').Last()} contract"))));
        }
    }

    private static void AddEventSubscriptions(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelEventSubscriptionDetection> detections,
        ICollection<Observation> observations)
    {
        foreach (var detection in detections)
        {
            var channel = EventChannelCandidate(project, detection.ChannelKey, detection.ChannelName,
                detection.EventType);
            var listenerDeclaration = project.Classes[detection.ListenerType];
            var listenerOwner = boundaries.OwnerByPath.GetValueOrDefault(listenerDeclaration.Path, boundaries.Deployable);
            var listenerOwnerCandidate = BoundaryCandidate(listenerOwner);
            var listenerContract = Candidate($"php:type:{project.ComposerPath}:{detection.ListenerType}",
                NodeKind.Component, detection.ListenerType.Split('\\').Last(), Resolution.Resolved,
                Properties(("language", "php"), ("type", detection.ListenerType),
                    ("role", "event-listener-contract"), ("queued", detection.Queued)));
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                detection.Rule, Confidence.Confirmed);
            observations.Add(Entity($"event-channel:{project.ComposerPath}:{detection.ChannelKey}", channel, seed));
            observations.Add(Entity($"listener-contract:{project.ComposerPath}:{detection.ListenerType}",
                listenerContract, seed));
            observations.Add(Relationship($"event-subscribe:{listenerOwner.Key}:{detection.ChannelKey}:" +
                                          $"{detection.ListenerType}:{detection.ListenerMethod}",
                EdgeKind.Subscribes, listenerOwnerCandidate, channel, seed,
                Properties(("messageType", "event"), ("event", detection.ChannelName),
                    ("listener", detection.ListenerType), ("listenerMethod", detection.ListenerMethod),
                    ("queued", detection.Queued),
                    ("label", $"subscribes to {detection.ChannelName.Split('\\').Last()}"))));
            observations.Add(Relationship($"listener-contract-use:{listenerOwner.Key}:{detection.ListenerType}",
                EdgeKind.UsesContract, listenerOwnerCandidate, listenerContract, seed,
                Properties(("contract", detection.ListenerType), ("queued", detection.Queued),
                    ("label", $"uses {detection.ListenerType.Split('\\').Last()} contract"))));
        }
    }

    private static EntityCandidate EventChannelCandidate(
        PhpProjectModel project, string channelKey, string channelName, string? eventType) =>
        Candidate($"php:laravel-event:{project.ComposerPath}:{channelKey}", NodeKind.MessageChannel,
            channelName, Resolution.Resolved,
            Properties(("messageType", "event"), ("event", channelName), ("contract", eventType)));

    private static EntityCandidate EventContractCandidate(PhpProjectModel project, string eventType) =>
        Candidate($"php:type:{project.ComposerPath}:{eventType}", NodeKind.Component,
            eventType.Split('\\').Last(), Resolution.Resolved,
            Properties(("language", "php"), ("type", eventType), ("role", "event-contract")));

    private static void AddSchedules(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelScheduleDetection> detections,
        ICollection<Observation> observations)
    {
        foreach (var detection in detections)
        {
            var owner = boundaries.OwnerByPath.GetValueOrDefault(detection.Path, boundaries.Deployable);
            var ownerCandidate = BoundaryCandidate(owner);
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, detection.Path, detection.Range,
                detection.Rule, Confidence.Confirmed);
            var cadence = ScheduleProperties(detection.Cadence);
            if (detection.TargetKind == LaravelScheduleTargetKind.Job && detection.TargetType is { } jobType)
            {
                var channel = Candidate($"php:laravel-job:{project.ComposerPath}:{jobType}",
                    NodeKind.MessageChannel, jobType, Resolution.Resolved,
                    Properties(("messageType", "job"), ("contract", jobType), ("queued", true)));
                var contract = Candidate($"php:type:{project.ComposerPath}:{jobType}",
                    NodeKind.Component, jobType.Split('\\').Last(), Resolution.Resolved,
                    Properties(("language", "php"), ("type", jobType), ("role", "queued-job-contract")));
                observations.Add(Entity($"schedule-job-channel:{project.ComposerPath}:{jobType}", channel, seed));
                observations.Add(Entity($"schedule-job-contract:{project.ComposerPath}:{jobType}", contract, seed));
                observations.Add(Relationship($"schedule-job-publish:{owner.Key}:{jobType}:{detection.TargetKey}",
                    EdgeKind.Publishes, ownerCandidate, channel, seed, cadence));
                observations.Add(Relationship($"schedule-job-contract:{owner.Key}:{jobType}",
                    EdgeKind.UsesContract, ownerCandidate, contract, seed,
                    Properties(("contract", jobType), ("scheduled", true),
                        ("label", $"uses {jobType.Split('\\').Last()} contract"))));
                continue;
            }

            var target = detection.TargetKind switch
            {
                LaravelScheduleTargetKind.Command => Candidate(
                    $"php:laravel-command:{project.ComposerPath}:{detection.TargetKey}", NodeKind.Component,
                    detection.TargetName, Resolution.Resolved,
                    Properties(("framework", "laravel"), ("role", "artisan-command"),
                        ("command", detection.TargetName))),
                LaravelScheduleTargetKind.Callback => Candidate(
                    $"php:scheduled-callback:{project.ComposerPath}:{detection.TargetKey}", NodeKind.Component,
                    detection.TargetName, Resolution.Resolved,
                    Properties(("language", "php"), ("role", "scheduled-callback"),
                        ("type", detection.TargetType), ("method", detection.TargetMethod))),
                _ => Candidate($"php:scheduled-closure:{project.ComposerPath}:{Stable(detection.TargetKey)}",
                    NodeKind.Component, detection.TargetName, Resolution.Unresolved,
                    Properties(("language", "php"), ("role", "scheduled-closure")))
            };
            observations.Add(Entity($"schedule-target:{project.ComposerPath}:{detection.TargetKind}:" +
                                    detection.TargetKey, target, seed));
            observations.Add(Relationship($"schedule-call:{owner.Key}:{detection.TargetKind}:" +
                                          detection.TargetKey, EdgeKind.Calls, ownerCandidate, target, seed, cadence));
        }
    }

    private static IReadOnlyDictionary<string, JsonElement> ScheduleProperties(LaravelScheduleCadence cadence) =>
        Properties(("scheduled", true), ("cadenceKind", cadence.Kind),
            ("cron", cadence.Expression), ("frequency", cadence.Frequency),
            ("intervalSeconds", cadence.IntervalSeconds), ("timezone", cadence.Timezone),
            ("label", cadence.Kind == "cron" ? $"scheduled {cadence.Expression}" :
                $"scheduled {cadence.Frequency}"));

    private static void AddEloquent(
        PhpProjectModel project,
        BoundaryDiscoveryResult boundaries,
        IReadOnlyList<LaravelEloquentModelDetection> models,
        IReadOnlyList<LaravelEloquentRelationDetection> relations,
        ICollection<Observation> observations)
    {
        foreach (var model in models)
        {
            var database = Candidate($"php:laravel-database:{project.ComposerPath}:{model.Connection}",
                NodeKind.Database, model.IsDefaultConnection ? "Laravel default database" : model.Connection,
                model.IsDefaultConnection ? Resolution.Unresolved : Resolution.Resolved,
                Properties(("framework", "laravel"), ("connection", model.Connection),
                    ("default", model.IsDefaultConnection)));
            var owner = boundaries.OwnerByPath.GetValueOrDefault(model.Path, boundaries.Deployable);
            var ownerCandidate = BoundaryCandidate(owner);
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, model.Path, model.Range,
                model.Rule, model.Confidence);
            observations.Add(Entity($"eloquent-database:{project.ComposerPath}:{model.Connection}", database, seed));
            observations.Add(Relationship($"eloquent-database-dependency:{owner.Key}:{model.Connection}:" +
                                          model.ModelType, EdgeKind.DependsOn, ownerCandidate, database, seed,
                Properties(("framework", "laravel"), ("access", "eloquent"),
                    ("model", model.ModelType), ("connection", model.Connection),
                    ("default", model.IsDefaultConnection),
                    ("label", model.IsDefaultConnection ? "uses unresolved Laravel default database" :
                        $"uses {model.Connection} database"))));
        }

        foreach (var relation in relations)
        {
            var sourceDeclaration = project.Classes[relation.ModelType];
            var targetDeclaration = project.Classes[relation.RelatedModelType];
            var sourceOwner = boundaries.OwnerByPath.GetValueOrDefault(sourceDeclaration.Path, boundaries.Deployable);
            var targetOwner = boundaries.OwnerByPath.GetValueOrDefault(targetDeclaration.Path, boundaries.Deployable);
            if (sourceOwner.Key == targetOwner.Key) continue;
            var sourceOwnerCandidate = BoundaryCandidate(sourceOwner);
            var targetOwnerCandidate = BoundaryCandidate(targetOwner);
            var contract = Candidate($"php:type:{project.ComposerPath}:{relation.RelatedModelType}",
                NodeKind.Component, relation.RelatedModelType.Split('\\').Last(), Resolution.Resolved,
                Properties(("language", "php"), ("type", relation.RelatedModelType),
                    ("role", "eloquent-model-contract")));
            var seed = new EvidenceSeed(EvidenceProvenance.Deterministic, relation.Path, relation.Range,
                relation.Rule, Confidence.Confirmed);
            observations.Add(Entity($"eloquent-model-contract:{project.ComposerPath}:" +
                                    relation.RelatedModelType, contract, seed));
            observations.Add(Relationship($"eloquent-model-relation:{sourceOwner.Key}:{targetOwner.Key}:" +
                                          $"{relation.ModelType}:{relation.RelatedModelType}:{relation.Relation}",
                EdgeKind.DependsOn, sourceOwnerCandidate, targetOwnerCandidate, seed,
                Properties(("framework", "laravel"), ("relation", relation.Relation),
                    ("model", relation.ModelType), ("relatedModel", relation.RelatedModelType),
                    ("usesContract", contract.Key),
                    ("label", $"{relation.Relation} {relation.RelatedModelType.Split('\\').Last()}"))));
        }
    }

    private static EntityCandidate ModuleCandidate(PhpProjectModel project) =>
        Candidate(project.Key, NodeKind.Module, project.Name, Resolution.Resolved,
            Properties(("dependencyType", "composer"), ("language", "php"),
                ("projectPath", project.ComposerPath)));

    private static EntityCandidate BoundaryCandidate(ApplicationBoundary boundary) =>
        Candidate(boundary.Key, boundary.Kind, boundary.Name, boundary.Resolution,
            Properties(("framework", boundary.Kind == NodeKind.Deployable ? "laravel" : null),
                ("language", "php"), ("projectPath", boundary.RootPath),
                ("moduleOrigin", boundary.Origin?.ToString().ToLowerInvariant())));

    private static EntityCandidate PackageCandidate(ComposerPackage package) =>
        Candidate($"php:composer-package:{package.Name}", NodeKind.Component, package.Name, package.Resolution,
            Properties(("dependencyType", "composer"), ("package", package.Name), ("language", "php")));

    private static EntityCandidate EndpointCandidate(
        PhpProjectModel project,
        LaravelEndpointDetection endpoint,
        bool ambiguous)
    {
        var baseKey = $"php:http-endpoint:{project.ComposerPath}:{EndpointIdentity(endpoint)}";
        var key = ambiguous
            ? $"{baseKey}:target:{Stable(TargetKey(endpoint))}"
            : baseKey;
        return Candidate(key, NodeKind.HttpEndpoint, $"{endpoint.Method} {endpoint.Template}",
            ambiguous ? Resolution.Ambiguous : endpoint.Resolution,
            Properties(("httpMethod", endpoint.Method), ("routeTemplate", endpoint.Template),
                ("domain", endpoint.Domain), ("routeName", endpoint.Name),
                ("controller", endpoint.Controller), ("action", endpoint.Action),
                ("ownerProject", project.ComposerPath), ("detectionRule", endpoint.Rule)));
    }

    private static string EndpointIdentity(LaravelEndpointDetection endpoint) =>
        endpoint.Domain is null
            ? $"{endpoint.Method}:{endpoint.Template}"
            : $"{endpoint.Method}:domain:{endpoint.Domain}:{endpoint.Template}";

    private static string TargetKey(LaravelEndpointDetection endpoint) =>
        $"{endpoint.Controller ?? string.Empty}\n{endpoint.Action ?? string.Empty}";

    private static EntityCandidate Candidate(
        string key,
        NodeKind kind,
        string name,
        Resolution resolution,
        IReadOnlyDictionary<string, JsonElement> properties) =>
        new(key, kind, null, name, resolution, new Dictionary<string, string>(), properties);

    private static EntityObservation Entity(string stableKey, EntityCandidate candidate, EvidenceSeed seed)
    {
        var id = $"observation:archie.php:{Stable($"{stableKey}\n{EvidenceKey(seed)}")}";
        return new(id, Evidence(id, seed), candidate);
    }

    private static RelationshipObservation Relationship(
        string stableKey,
        EdgeKind kind,
        EntityCandidate from,
        EntityCandidate to,
        EvidenceSeed seed,
        IReadOnlyDictionary<string, JsonElement> properties)
    {
        var id = $"observation:archie.php:{Stable($"{stableKey}\n{EvidenceKey(seed)}")}";
        return new(id, Evidence(id, seed), kind, from, to, properties);
    }

    private static IEnumerable<EvidenceSeed> Evidence(ApplicationBoundary boundary) =>
        new[] { boundary.Evidence }.Concat(boundary.SupportingEvidence)
            .Distinct().OrderBy(EvidenceKey, StringComparer.Ordinal);

    private static string EvidenceKey(EvidenceSeed seed) =>
        $"{seed.Provenance}:{seed.Path}:{seed.Range?.StartLine}:{seed.Range?.StartColumn}:" +
        $"{seed.Range?.EndLine}:{seed.Range?.EndColumn}:{seed.Rule}:{seed.Confidence}";

    private static Evidence Evidence(string observationId, EvidenceSeed seed) =>
        new($"evidence:{observationId}", observationId, seed.Provenance,
            ScannerId, ScannerVersion, seed.Rule, seed.Path.Replace('\\', '/'), seed.Range, seed.Confidence,
            Properties(("detectionRule", seed.Rule), ("observationSource", "scanner")));

    private static IReadOnlyDictionary<string, JsonElement> Properties(params (string Name, object? Value)[] values) =>
        values.Where(item => item.Value is not null).ToDictionary(
            item => item.Name,
            item => JsonSerializer.SerializeToElement(item.Value, item.Value!.GetType()),
            StringComparer.Ordinal);

    private static bool IsWithinPath(string path, string directory) =>
        directory.Length == 0 || path.StartsWith($"{directory}/", PathComparison());

    private static Diagnostic Diagnostic(string code, string message, string? subject, string key) =>
        new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}", code, "warning", message, subject);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private static StringComparison PathComparison() => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}
