using System.Diagnostics;
using System.Text;
using Archie.Scanner.Php;
using Xunit;
using ContractJson = Entorn.Scanner.Contracts.ScannerContractJson;

namespace Archie.Scanner.Php.Tests;

public sealed class PhpScannerTests
{
    [Fact]
    public void BundledPhpGrammarLoadsAndReturnsOneBasedSourceRanges()
    {
        using var syntax = new PhpSyntax();
        var aggregateNodes = 0;

        var result = syntax.Validate("<?php\nfinal class Basket {}\n", new(), ref aggregateNodes, CancellationToken.None);

        Assert.False(result.HasErrors);
        Assert.True(result.NodeCount > 1);
        Assert.Equal(result.NodeCount, aggregateNodes);
        Assert.Equal(1, result.Range.StartLine);
        Assert.Equal(1, result.Range.StartColumn);
        Assert.True(result.Range.EndLine >= 2);
    }

    [Fact]
    public void WorkerBudgetsMatchTheTrustedScannerSupervisor()
    {
        Assert.Equal(1024 * 1024, PhpWorkerLimits.MaxRequestBytes);
        Assert.Equal(1024 * 1024, PhpWorkerLimits.MaxProtocolMessageBytes);
        Assert.Equal(128L * 1024 * 1024, PhpWorkerLimits.MaxSerializedOutputBytes);
        Assert.Equal(100_000, PhpWorkerLimits.MaxObservations);
    }

    [Fact]
    public void ApprovedAggregateSyntaxDefaultPreservesAllSurroundingLimits()
    {
        var limits = new PhpScannerLimits();

        Assert.Equal(20_000, limits.MaxInputFiles);
        Assert.Equal(64 * 1024 * 1024, limits.MaxInputBytes);
        Assert.Equal(2 * 1024 * 1024, limits.MaxPhpFileBytes);
        Assert.Equal(8 * 1024 * 1024, limits.MaxMetadataFileBytes);
        Assert.Equal(250_000, limits.MaxSyntaxNodesPerFile);
        Assert.Equal(4 * 1024 * 1024, limits.MaxSyntaxNodes);
        Assert.Equal(256, limits.MaxSyntaxDepth);
        Assert.Equal(10_000, limits.MaxComposerPackages);
        Assert.Equal(10_000, limits.MaxDiagnostics);
        Assert.Equal(256 * 1024, limits.MaxDiscoveryConfigurationBytes);
        Assert.Equal(256, limits.MaxConfiguredModules);
        Assert.Equal(4 * 1024 * 1024, limits.MaxSnapshotFileBytes);
        Assert.Equal(16, limits.MaxSnapshotJsonDepth);
        Assert.Equal(10_000, limits.MaxSnapshotRecordsPerFile);
        Assert.Equal(256, limits.MaxSnapshotCollectionItems);
        Assert.Equal(4_096, limits.MaxSnapshotStringLength);
        Assert.Equal(250_000, limits.MaxSymbols);
        Assert.Equal(1_000_000, limits.MaxReferences);
        Assert.Equal(100_000, limits.MaxDetections);
    }

    [Fact]
    public void WorkerPreflightsObservationMessageAndSerializedOutputLimitsBeforeEmission()
    {
        Assert.False(PhpWorkerProtocol.FitsOutput("ready", ["small"], 2, out var observationCode,
            maxObservations: 1, maxMessageBytes: 100, maxOutputBytes: 100));
        Assert.Equal("PHP_WORKER_OBSERVATION_LIMIT_EXCEEDED", observationCode);
        Assert.False(PhpWorkerProtocol.FitsOutput("ready", ["oversized"], 0, out var messageCode,
            maxObservations: 1, maxMessageBytes: 3, maxOutputBytes: 100));
        Assert.Equal("PHP_WORKER_OUTPUT_LIMIT_EXCEEDED", messageCode);
        Assert.False(PhpWorkerProtocol.FitsOutput("ready", ["one", "two"], 0, out var outputCode,
            maxObservations: 1, maxMessageBytes: 100, maxOutputBytes: 10));
        Assert.Equal("PHP_WORKER_OUTPUT_LIMIT_EXCEEDED", outputCode);
    }

    [Fact]
    public async Task GenericComposerProjectProducesModuleAndLockedDirectPackageDependencies()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            {
              "name": "archie/php-reference",
              "require": { "php": "^8.3", "psr/log": "^3.0" },
              "autoload": { "psr-4": { "Reference\\": "src/" } }
            }
            """);
        await Write(temporary.Path, "composer.lock", """
            { "packages": [{ "name": "psr/log", "version": "3.0.2" }], "packages-dev": [] }
            """);
        await Write(temporary.Path, "src/Basket.php", "<?php\nnamespace Reference;\nfinal class Basket {}\n");

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);
        var entities = result.Observations.OfType<EntityObservation>().ToArray();
        var relationships = result.Observations.OfType<RelationshipObservation>().ToArray();

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Contains(entities, item => item.Entity.Key == "php:composer-project:composer.json" &&
            item.Entity.Kind == NodeKind.Module && item.Entity.Properties["language"].GetString() == "php");
        Assert.Contains(entities, item => item.Entity.Key == "php:composer-package:psr/log" &&
            item.Entity.Kind == NodeKind.Component && item.Entity.Resolution == Resolution.Resolved);
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.DependsOn &&
            item.From.Key == "php:composer-project:composer.json" && item.To.Key == "php:composer-package:psr/log" &&
            item.Properties["requestedVersion"].GetString() == "^3.0" &&
            item.Properties["lockedVersion"].GetString() == "3.0.2");
        Assert.Contains(result.SourceOwnership, item => item.Path == "src/Basket.php" &&
            item.OwnerCandidateKey == "php:composer-project:composer.json" && item.DerivationRule == "composer:psr-4-class-ownership");
        Assert.DoesNotContain(entities, item => item.Entity.Kind == NodeKind.Deployable);
    }

    [Fact]
    public async Task RepresentativeScaleSemanticCorpusFitsTheApprovedAggregateLimit()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/representative-scale", "autoload": { "psr-4": { "Representative\\": "src/" } } }
            """);
        for (var index = 0; index < 4_021; index++)
        {
            var source = new StringBuilder($"<?php\nnamespace Representative\\N{index:D4};\nfinal class C{index:D4} {{\n");
            for (var method = 0; method < 19; method++)
                source.Append("public function m").Append(method.ToString("D2"))
                    .Append("(): int { $a = 1; $b = $a + 2; return $b; }\n");
            source.Append("}\n");
            source.Append("/*").Append('x', 2_956 - source.Length).Append("*/\n");
            await Write(temporary.Path, $"src/N{index:D4}/C{index:D4}.php", source.ToString());
        }

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Equal(4_021, result.SourceOwnership.Count);
    }

    [Fact]
    public async Task MissingLockPackageRemainsVisibleAndUnresolved()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/php-reference", "require": { "vendor/library": "^1.0" } }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Key == "php:composer-package:vendor/library" && item.Entity.Resolution == Resolution.Unresolved);
    }

    [Fact]
    public async Task LockedConventionalLaravelProjectProducesDeployableWithoutExecutingTargetCode()
    {
        using var temporary = new TemporaryDirectory();
        var marker = Path.Combine(temporary.Path, "target-code-ran");
        await WriteLaravelProject(temporary.Path, marker);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);
        var entities = result.Observations.OfType<EntityObservation>().ToArray();
        var relationships = result.Observations.OfType<RelationshipObservation>().ToArray();

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.False(File.Exists(marker));
        Assert.DoesNotContain(entities, item => item.Entity.Key == "php:composer-project:composer.json");
        Assert.Contains(entities, item => item.Entity.Key == "php:laravel-app:composer.json" &&
            item.Entity.Kind == NodeKind.Deployable && item.Entity.Properties["framework"].GetString() == "laravel");
        Assert.DoesNotContain(relationships, item => item.Relationship == EdgeKind.Contains &&
            item.From.Key == "php:composer-project:composer.json");
        Assert.Contains(entities, item => item.Entity.Kind == NodeKind.HttpEndpoint &&
            item.Entity.Name == "POST /storefront/orders" && item.Entity.Resolution == Resolution.Resolved);
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Exposes &&
            item.From.Key == "php:laravel-app:composer.json" &&
            item.To.Key == "php:http-endpoint:composer.json:POST:/storefront/orders" &&
            item.Evidence.Path == "routes/web.php" && item.Evidence.Range?.StartLine == 4);
        Assert.All(result.Observations, observation =>
        {
            Assert.Equal(EvidenceProvenance.Deterministic, observation.Evidence.Provenance);
            Assert.Equal("archie.php", observation.Evidence.ScannerId);
        });
    }

    [Fact]
    public async Task LaravelClassificationRequiresDirectLockedFrameworkAndConventionalMarkers()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/not-laravel", "require": { "php": "^8.3" } }
            """);
        await Write(temporary.Path, "composer.lock", """
            { "packages": [{ "name": "laravel/framework", "version": "v12.0.0" }], "packages-dev": [] }
            """);
        await Write(temporary.Path, "artisan", "#!/usr/bin/env php\n<?php\n");
        await Write(temporary.Path, "bootstrap/app.php", "<?php\nreturn null;\n");
        await Write(temporary.Path, "routes/web.php", "<?php\n");
        await Write(temporary.Path, "app/Http/Controllers/HomeController.php", "<?php\nfinal class HomeController {}\n");

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(), item => item.Entity.Kind == NodeKind.Deployable);
    }

    [Fact]
    public async Task DuplicateLockedFrameworkDoesNotClassifyLaravelAsResolved()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "composer.lock", """
            {
              "packages": [
                { "name": "laravel/framework", "version": "v12.0.0" },
                { "name": "Laravel/Framework", "version": "v12.0.0" }
              ],
              "packages-dev": []
            }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(), item => item.Entity.Kind == NodeKind.Deployable);
        Assert.Contains(result.Diagnostics, item => item.Code == "PHP_COMPOSER_PACKAGE_AMBIGUOUS");
    }

    [Fact]
    public async Task DynamicAndLookalikeRoutesAreIgnoredWhileLiteralGroupsAreDiscovered()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "routes/web.php", """
            <?php
            use Acme\Support\Route;
            use App\Http\Controllers\CheckoutController;
            use Illuminate\Support\Facades\Route as LaravelRoute;
            Route::post('/lookalike', [CheckoutController::class, 'store']);
            LaravelRoute::post($path, [CheckoutController::class, 'store']);
            LaravelRoute::group([], function () {
                LaravelRoute::post('/grouped', [CheckoutController::class, 'store']);
            });
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Kind == NodeKind.HttpEndpoint && item.Entity.Name == "POST /grouped");
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ROUTE_UNSUPPORTED");
    }

    [Fact]
    public async Task ImportedRouteRequiresPsr4ControllerAndDeclaredAction()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "routes/web.php", """
            <?php
            use App\Http\Controllers\MissingController;
            use Illuminate\Support\Facades\Route;
            Route::post('/storefront/orders', [MissingController::class, 'store']);
            """);
        await Write(temporary.Path, "app/WrongPlace/MissingController.php", """
            <?php
            namespace App\Http\Controllers;
            final class MissingController { public function store(): void {} }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Kind == NodeKind.HttpEndpoint && item.Entity.Resolution == Resolution.Unresolved);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_CONTROLLER_UNRESOLVED");
    }

    [Fact]
    public async Task DuplicateRoutesRetainEvidenceForOneResolvedCandidate()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "routes/web.php", """
            <?php
            use App\Http\Controllers\CheckoutController;
            use Illuminate\Support\Facades\Route;
            Route::post('/storefront/orders', [CheckoutController::class, 'store']);
            Route::post('/storefront/orders', [CheckoutController::class, 'store']);
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);
        var endpoints = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Kind == NodeKind.HttpEndpoint).ToArray();

        Assert.True(result.Succeeded);
        Assert.Equal(2, endpoints.Length);
        Assert.All(endpoints, item => Assert.Equal(Resolution.Resolved, item.Entity.Resolution));
        Assert.Single(endpoints.Select(item => item.Entity.Key).Distinct(StringComparer.Ordinal));
        Assert.DoesNotContain(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ENDPOINT_AMBIGUOUS");
    }

    [Fact]
    public async Task LiteralRouteFamiliesPreserveGroupsActionsNamesDomainsAndConflicts()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "app/Http/Controllers/RouteController.php", """
            <?php
            namespace App\Http\Controllers;
            final class RouteController {
                public function index(): void {}
                public function create(): void {}
                public function store(): void {}
                public function show(): void {}
                public function edit(): void {}
                public function update(): void {}
                public function destroy(): void {}
            }
            final class InvokableController { public function __invoke(): void {} }
            """);
        await Write(temporary.Path, "routes/web.php", """
            <?php
            use App\Http\Controllers\InvokableController;
            use App\Http\Controllers\RouteController;
            use Illuminate\Support\Facades\Route;
            Route::head('/health', fn () => null);
            Route::options('/health', InvokableController::class);
            Route::match(['get', 'post'], '/search', [RouteController::class, 'index']);
            Route::any('/hook', 'App\Http\Controllers\RouteController@store');
            Route::resource('orders', RouteController::class);
            Route::apiResource('customers', RouteController::class);
            Route::prefix('api')->domain('store.example.test')->name('api.')->controller(RouteController::class)->group(function () {
                Route::get('orders', 'index')->name('orders');
                Route::prefix('v2')->group(function () {
                    Route::get('status', fn () => null);
                });
            });
            Route::domain('admin.example.test')->group(function () {
                Route::get('/orders', [RouteController::class, 'show']);
            });
            Route::get('/conflict', [RouteController::class, 'show']);
            Route::get('/conflict', [RouteController::class, 'missing']);
            if ($enabled) Route::get('/conditional', fn () => null);
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);
        var endpoints = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Kind == NodeKind.HttpEndpoint).ToArray();

        Assert.True(result.Succeeded);
        Assert.Contains(endpoints, item => item.Entity.Name == "HEAD /health" &&
            item.Evidence.Confidence == Confidence.Inferred);
        Assert.Contains(endpoints, item => item.Entity.Name == "OPTIONS /health" &&
            item.Entity.Properties["action"].GetString() == "__invoke");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /search");
        Assert.Contains(endpoints, item => item.Entity.Name == "POST /search");
        Assert.Equal(7, endpoints.Count(item => item.Entity.Properties.GetValueOrDefault("routeTemplate").GetString() == "/hook"));
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /orders/{order}/edit");
        Assert.DoesNotContain(endpoints, item => item.Entity.Name == "GET /customers/create");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/orders" &&
            item.Entity.Properties["domain"].GetString() == "store.example.test" &&
            item.Entity.Properties["routeName"].GetString() == "api.orders");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/v2/status" &&
            item.Evidence.Confidence == Confidence.Inferred);
        Assert.Equal(2, endpoints.Where(item => item.Entity.Name == "GET /conflict").Select(item => item.Entity.Key)
            .Distinct(StringComparer.Ordinal).Count());
        Assert.All(endpoints.Where(item => item.Entity.Name == "GET /conflict"),
            item => Assert.Equal(Resolution.Ambiguous, item.Entity.Resolution));
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ENDPOINT_AMBIGUOUS");
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ROUTE_UNSUPPORTED");
    }

    [Fact]
    public async Task IndexedServiceProviderRegistrationIsSupportedOutsideRouteFiles()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "app/Providers/RouteServiceProvider.php", """
            <?php
            namespace App\Providers;
            use App\Http\Controllers\CheckoutController;
            use Illuminate\Support\Facades\Route;
            use Illuminate\Support\ServiceProvider;
            final class RouteServiceProvider extends ServiceProvider {
                public function boot(): void {
                    Route::get('/provider', [CheckoutController::class, 'store']);
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Kind == NodeKind.HttpEndpoint && item.Entity.Name == "GET /provider");
    }

    [Fact]
    public async Task SpatieRouteAttributesArePackageBoundLiteralAndStructurallyOwned()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "composer.json", """
            {
              "name": "archie/laravel-storefront",
              "require": {
                "laravel/framework": "^12.0",
                "spatie/laravel-route-attributes": "^1.0"
              },
              "autoload": { "psr-4": { "App\\": "app/" } }
            }
            """);
        await Write(temporary.Path, "composer.lock", """
            {
              "packages": [
                { "name": "laravel/framework", "version": "v12.0.0" },
                { "name": "spatie/laravel-route-attributes", "version": "1.27.0" }
              ],
              "packages-dev": []
            }
            """);
        await Write(temporary.Path, "app/Http/Controllers/AttributedController.php", """
            <?php
            namespace App\Http\Controllers;
            use Spatie\RouteAttributes\Attributes\Domain;
            use Spatie\RouteAttributes\Attributes\Get;
            use Spatie\RouteAttributes\Attributes\Post;
            use Spatie\RouteAttributes\Attributes\Prefix;
            use Spatie\RouteAttributes\Attributes\Route;
            #[Prefix('api')]
            #[Domain('store.example.test')]
            final class AttributedController {
                #[Get('orders', name: 'orders.index')]
                #[Get('orders/export', name: 'orders.export')]
                public function index(): void {}
                #[Post(uri: 'orders')]
                public function store(): void {}
                #[Route(methods: ['PATCH', 'DELETE'], uri: 'orders/{order}', name: 'orders.change')]
                public function change(): void {}
                #[\Spatie\RouteAttributes\Attributes\Get('fqcn')]
                public function fqcn(): void {}
                #[Get($dynamic)]
                public function dynamic(): void {}
            }
            """);
        await Write(temporary.Path, "app/Http/Controllers/CustomerController.php", """
            <?php
            namespace App\Http\Controllers;
            use Spatie\RouteAttributes\Attributes\ApiResource;
            #[ApiResource('customers', only: ['index', 'show'])]
            final class CustomerController {
                public function index(): void {}
                public function show(): void {}
            }
            """);
        await Write(temporary.Path, "app/Http/Controllers/LookalikeController.php", """
            <?php
            namespace App\Http\Controllers;
            use Acme\Attributes\Get;
            final class LookalikeController {
                #[Get('/lookalike')]
                public function index(): void {}
            }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);
        var endpoints = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Kind == NodeKind.HttpEndpoint).ToArray();

        Assert.True(result.Succeeded);
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/orders" &&
            item.Entity.Properties["domain"].GetString() == "store.example.test" &&
            item.Entity.Properties["routeName"].GetString() == "orders.index" &&
            item.Entity.Properties["controller"].GetString() == "App\\Http\\Controllers\\AttributedController" &&
            item.Entity.Properties["action"].GetString() == "index" &&
            item.Evidence.Confidence == Confidence.Inferred);
        Assert.Contains(endpoints, item => item.Entity.Name == "POST /api/orders");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/orders/export" &&
            item.Entity.Properties["routeName"].GetString() == "orders.export");
        Assert.Contains(endpoints, item => item.Entity.Name == "PATCH /api/orders/{order}");
        Assert.Contains(endpoints, item => item.Entity.Name == "DELETE /api/orders/{order}");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/fqcn");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /customers");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /customers/{customer}");
        Assert.DoesNotContain(endpoints, item => item.Entity.Name.Contains("lookalike", StringComparison.Ordinal));
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ROUTE_ATTRIBUTE_UNSUPPORTED");
    }

    [Fact]
    public async Task SpatieNamedAttributesDoNotCreateRoutesWithoutTheProductionPackage()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "app/Http/Controllers/AttributedController.php", """
            <?php
            namespace App\Http\Controllers;
            use Spatie\RouteAttributes\Attributes\Get;
            final class AttributedController {
                #[Get('/attribute-without-package')]
                public function index(): void {}
            }
            """);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Kind == NodeKind.HttpEndpoint && item.Entity.Name == "GET /attribute-without-package");
    }

    [Fact]
    public async Task LaravelHttpCallsEmitOnlyNormalizedOriginsWithSourceModuleOwnership()
    {
        using var repository = new TestRepository();
        var marker = Path.Combine(repository.Path, "must-not-exist");
        await repository.WriteLaravelAsync(marker);
        await repository.WriteAsync("src/Billing/PaymentGateway.php", """
            <?php
            namespace Company\Billing;
            use Illuminate\Support\Facades\Http as Client;
            final class PaymentGateway {
                public function charge(): void {
                    Client::get('HTTPS://BÜCHER.example:443/orders?token=QUERY_SECRET');
                    Client::post('https://API.EXAMPLE.test:8443/payments', ['card' => 'BODY_SECRET']);
                    Client::baseUrl('https://api.example.test/v1/')
                        ->withToken('TOKEN_SECRET')
                        ->withHeaders(['X-Key' => 'HEADER_SECRET'])
                        ->get('orders?signature=PATH_SECRET');
                    Client::get('https://api.example.test/duplicate-evidence');
                    Client::send('GET', url: 'http://plain.example.test:80/private');
                    Client::get('http://[2001:db8::1]:8080/private');
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var services = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Kind == NodeKind.ExternalService).ToArray();
        var calls = result.Observations.OfType<RelationshipObservation>()
            .Where(item => item.Relationship == EdgeKind.Calls).ToArray();
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.Contains(services, item => item.Entity.Key ==
            "php:external-service:https://xn--bcher-kva.example");
        Assert.Contains(services, item => item.Entity.Key ==
            "php:external-service:https://api.example.test:8443" &&
            item.Entity.Properties["port"].GetInt32() == 8443);
        Assert.Contains(services, item => item.Entity.Key == "php:external-service:https://api.example.test");
        Assert.Equal(2, services.Count(item =>
            item.Entity.Key == "php:external-service:https://api.example.test"));
        Assert.Contains(services, item => item.Entity.Key == "php:external-service:http://plain.example.test");
        Assert.Contains(services, item => item.Entity.Key == "php:external-service:http://[2001:db8::1]:8080");
        Assert.All(calls, item => Assert.Equal("php:module:composer.json:src/Billing", item.From.Key));
        Assert.DoesNotContain("/orders", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("/payments", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("QUERY_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("BODY_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("TOKEN_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("HEADER_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("PATH_SECRET", serialized, StringComparison.Ordinal);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public async Task UnsafeDynamicAndLookalikeHttpCallsDoNotCreateServicesOrLeakValues()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Billing/UnsafeGateway.php", """
            <?php
            namespace Company\Billing;
            use Acme\Support\Http;
            use Illuminate\Support\Facades\Http as LaravelHttp;
            final class UnsafeGateway {
                public function call(string $host): void {
                    Http::get('https://lookalike.example/secret');
                    LaravelHttp::get('https://user:CREDENTIAL_SECRET@private.example/path');
                    LaravelHttp::get("https://{$host}/INTERPOLATED_SECRET");
                    LaravelHttp::get('ftp://files.example/FTP_SECRET');
                    LaravelHttp::get('https://bad host.example/INVALID_SECRET');
                    LaravelHttp::get('https://bad_host.example/UNDERSCORE_SECRET');
                    LaravelHttp::baseUrl($host)->get('/VARIABLE_SECRET');
                    LaravelHttp::withToken('TOKEN_SECRET')->get('/NO_BASE_SECRET');
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(),
            item => item.Entity.Kind == NodeKind.ExternalService);
        Assert.Equal(7, result.Diagnostics.Count(item => item.Code == "PHP_LARAVEL_HTTP_UNSUPPORTED"));
        Assert.DoesNotContain("CREDENTIAL_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("INTERPOLATED_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("FTP_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("INVALID_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("UNDERSCORE_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("VARIABLE_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("TOKEN_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("NO_BASE_SECRET", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RouteAndHttpDetectionsShareOneFailClosedBudget()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Billing/Gateway.php", """
            <?php
            namespace Company\Billing;
            use Illuminate\Support\Facades\Http;
            final class Gateway {
                public function call(): void { Http::get('https://api.example.test/path'); }
            }
            """);

        var result = await new PhpScanner(new(MaxDetections: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_DETECTION_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task CompleteStaticDiscoverySharesOneFailClosedDetectionBudget()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Billing/Models/Invoice.php", """
            <?php
            namespace Company\Billing\Models;
            use Illuminate\Database\Eloquent\Model;
            final class Invoice extends Model { protected $connection = 'ledger'; }
            """);
        await repository.WriteAsync("routes/console.php", """
            <?php
            use Illuminate\Support\Facades\Schedule;
            Schedule::command('billing:close')->daily();
            """);

        var result = await new PhpScanner(new(MaxDetections: 2))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_DETECTION_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task DetectionBudgetIsSharedAcrossNestedLaravelProjects()
    {
        using var repository = new TemporaryDirectory();
        await WriteLaravelProject(Path.Combine(repository.Path, "one"), Path.Combine(repository.Path, "must-not-exist"));
        await WriteLaravelProject(Path.Combine(repository.Path, "two"), Path.Combine(repository.Path, "must-not-exist"));

        var result = await new PhpScanner(new(MaxDetections: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_DETECTION_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task QueuedJobDispatchFormsPublishOneTransitiveContractWithoutPayloads()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Shipping/Contracts/QueuedWork.php", """
            <?php
            namespace Company\Shipping\Contracts;
            use Illuminate\Contracts\Queue\ShouldQueue;
            interface QueuedWork extends ShouldQueue {}
            """);
        await repository.WriteAsync("src/Shipping/Jobs/BaseJob.php", """
            <?php
            namespace Company\Shipping\Jobs;
            use Company\Shipping\Contracts\QueuedWork;
            abstract class BaseJob implements QueuedWork {}
            """);
        await repository.WriteAsync("src/Shipping/Jobs/ImportCatalog.php", """
            <?php
            namespace Company\Shipping\Jobs;
            final class ImportCatalog extends BaseJob {}
            """);
        await repository.WriteAsync("src/Shipping/Jobs/PlainJob.php", """
            <?php
            namespace Company\Shipping\Jobs;
            final class PlainJob {}
            """);
        await repository.WriteAsync("src/Billing/JobDispatcher.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Jobs\ImportCatalog;
            use Company\Shipping\Jobs\PlainJob;
            use Acme\Support\Bus as FakeBus;
            use Illuminate\Support\Facades\Bus;
            use Illuminate\Support\Facades\Queue;
            final class JobDispatcher {
                public function dispatchAll(object $dynamic): void {
                    ImportCatalog::dispatch('STATIC_PAYLOAD_SECRET');
                    ImportCatalog::dispatchSync('SYNC_PAYLOAD_SECRET');
                    dispatch(new ImportCatalog('HELPER_PAYLOAD_SECRET'));
                    Bus::dispatch(new ImportCatalog('BUS_PAYLOAD_SECRET'));
                    Queue::push(new ImportCatalog('QUEUE_PAYLOAD_SECRET'));
                    FakeBus::dispatch(new ImportCatalog('FAKE_BUS_SECRET'));
                    PlainJob::dispatch('IGNORED_NONQUEUED_SECRET');
                    dispatch(new PlainJob('NONQUEUED_SECRET'));
                    dispatch($dynamic);
                    Bus::dispatch(new MissingJob('MISSING_SECRET'));
                }
            }
            """);
        await repository.WriteAsync("src/Billing/ImportedLookalike.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Jobs\ImportCatalog;
            use function Acme\dispatch;
            final class ImportedLookalike {
                public function run(): void { dispatch(new ImportCatalog('LOOKALIKE_SECRET')); }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var channelKey = "php:laravel-job:composer.json:Company\\Shipping\\Jobs\\ImportCatalog";
        var contractKey = "php:type:composer.json:Company\\Shipping\\Jobs\\ImportCatalog";
        var channels = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Key == channelKey).ToArray();
        var contracts = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Key == contractKey).ToArray();
        var publishes = result.Observations.OfType<RelationshipObservation>()
            .Where(item => item.Relationship == EdgeKind.Publishes && item.To.Key == channelKey).ToArray();
        var usesContracts = result.Observations.OfType<RelationshipObservation>()
            .Where(item => item.Relationship == EdgeKind.UsesContract && item.To.Key == contractKey).ToArray();
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.Equal(5, channels.Length);
        Assert.Equal(5, contracts.Length);
        Assert.Equal(5, publishes.Length);
        Assert.Equal(5, usesContracts.Length);
        Assert.All(publishes, item => Assert.Equal("php:module:composer.json:src/Billing", item.From.Key));
        Assert.All(channels, item =>
        {
            Assert.True(item.Entity.Properties["queued"].GetBoolean());
            Assert.Equal("job", item.Entity.Properties["messageType"].GetString());
        });
        Assert.Equal(3, result.Diagnostics.Count(item => item.Code == "PHP_LARAVEL_JOB_UNSUPPORTED"));
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Name.Contains("PlainJob", StringComparison.Ordinal));
        foreach (var secret in new[] { "STATIC_PAYLOAD_SECRET", "SYNC_PAYLOAD_SECRET", "HELPER_PAYLOAD_SECRET",
                     "BUS_PAYLOAD_SECRET", "QUEUE_PAYLOAD_SECRET", "IGNORED_NONQUEUED_SECRET",
                     "NONQUEUED_SECRET", "MISSING_SECRET", "LOOKALIKE_SECRET", "FAKE_BUS_SECRET" })
            Assert.DoesNotContain(secret, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EventEmissionAndExplicitListenersProduceOwnedChannelsAndContractsWithoutPayloads()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Shipping/Events/DomainDispatchable.php", """
            <?php
            namespace Company\Shipping\Events;
            use Illuminate\Foundation\Events\Dispatchable;
            trait DomainDispatchable { use Dispatchable; }
            """);
        await repository.WriteAsync("src/Shipping/Events/ShipmentCreated.php", """
            <?php
            namespace Company\Shipping\Events;
            final class ShipmentCreated { use DomainDispatchable; }
            """);
        await repository.WriteAsync("src/Shipping/Contracts/QueuedListener.php", """
            <?php
            namespace Company\Shipping\Contracts;
            use Illuminate\Contracts\Queue\ShouldQueue;
            interface QueuedListener extends ShouldQueue {}
            """);
        await repository.WriteAsync("src/Shipping/Listeners/NotifyWarehouse.php", """
            <?php
            namespace Company\Shipping\Listeners;
            use Company\Shipping\Contracts\QueuedListener;
            final class NotifyWarehouse implements QueuedListener { public function handle(): void {} }
            """);
        await repository.WriteAsync("src/Shipping/Listeners/RecordShipment.php", """
            <?php
            namespace Company\Shipping\Listeners;
            final class RecordShipment {
                public function handle(): void {}
                public function whenShipmentCreated(): void {}
            }
            """);
        await repository.WriteAsync("src/Shipping/Listeners/ConventionOnly.php", """
            <?php
            namespace Company\Shipping\Listeners;
            final class ConventionOnly { public function handle(): void {} }
            """);
        await repository.WriteAsync("src/Billing/EventEmitter.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Illuminate\Support\Facades\Event;
            final class EventEmitter {
                public function emit(object $dynamic): void {
                    event(new ShipmentCreated('HELPER_EVENT_PAYLOAD_SECRET'));
                    Event::dispatch(new ShipmentCreated('FACADE_EVENT_PAYLOAD_SECRET'));
                    ShipmentCreated::dispatch('STATIC_EVENT_PAYLOAD_SECRET');
                    event('order.paid', ['token' => 'STRING_HELPER_PAYLOAD_SECRET']);
                    Event::dispatch('order.paid', ['token' => 'STRING_FACADE_PAYLOAD_SECRET']);
                    event($dynamic);
                }
            }
            """);
        await repository.WriteAsync("src/Billing/EventRegistrar.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Company\Shipping\Listeners\NotifyWarehouse;
            use Company\Shipping\Listeners\RecordShipment;
            use Illuminate\Support\Facades\Event;
            final class EventRegistrar {
                public function boot(object $dynamic): void {
                    Event::listen(ShipmentCreated::class, [NotifyWarehouse::class, 'handle']);
                    Event::listen('order.paid', RecordShipment::class);
                    Event::listen($dynamic, RecordShipment::class);
                    Event::listen('dynamic.listener', $dynamic);
                }
            }
            """);
        await repository.WriteAsync("src/Billing/EventServiceProvider.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Company\Shipping\Listeners\NotifyWarehouse;
            use Company\Shipping\Listeners\RecordShipment;
            use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
            final class EventServiceProvider extends ServiceProvider {
                protected $listen = [
                    ShipmentCreated::class => [
                        NotifyWarehouse::class,
                        [RecordShipment::class, 'whenShipmentCreated'],
                    ],
                    'order.paid' => [RecordShipment::class],
                ];
            }
            """);
        await repository.WriteAsync("src/Billing/EventLookalikes.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Acme\Support\Event;
            use function Acme\event;
            final class EventLookalikes {
                public function run(): void {
                    Event::dispatch(new ShipmentCreated('FACADE_LOOKALIKE_SECRET'));
                    event(new ShipmentCreated('HELPER_LOOKALIKE_SECRET'));
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var classChannelKey =
            "php:laravel-event:composer.json:class:Company\\Shipping\\Events\\ShipmentCreated";
        var stringChannelKey = "php:laravel-event:composer.json:name:order.paid";
        var eventContractKey = "php:type:composer.json:Company\\Shipping\\Events\\ShipmentCreated";
        var queuedListenerKey = "php:type:composer.json:Company\\Shipping\\Listeners\\NotifyWarehouse";
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));
        var relationships = result.Observations.OfType<RelationshipObservation>().ToArray();

        Assert.True(result.Succeeded);
        Assert.Equal(3, relationships.Count(item => item.Relationship == EdgeKind.Publishes &&
            item.To.Key == classChannelKey && item.From.Key == "php:module:composer.json:src/Billing"));
        Assert.Equal(2, relationships.Count(item => item.Relationship == EdgeKind.Publishes &&
            item.To.Key == stringChannelKey && item.From.Key == "php:module:composer.json:src/Billing"));
        Assert.Equal(3, relationships.Count(item => item.Relationship == EdgeKind.UsesContract &&
            item.To.Key == eventContractKey && item.From.Key == "php:module:composer.json:src/Billing"));
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Subscribes &&
            item.To.Key == classChannelKey && item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.Properties["listener"].GetString() == "Company\\Shipping\\Listeners\\NotifyWarehouse" &&
            item.Properties["queued"].GetBoolean());
        Assert.Equal(2, relationships.Count(item => item.Relationship == EdgeKind.Subscribes &&
            item.To.Key == classChannelKey &&
            item.Properties["listener"].GetString() == "Company\\Shipping\\Listeners\\NotifyWarehouse"));
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Subscribes &&
            item.To.Key == classChannelKey &&
            item.Properties["listenerMethod"].GetString() == "whenShipmentCreated");
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Subscribes &&
            item.To.Key == stringChannelKey && item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.Properties["listenerMethod"].GetString() == "handle");
        Assert.Equal(2, relationships.Count(item => item.Relationship == EdgeKind.Subscribes &&
            item.To.Key == stringChannelKey &&
            item.Properties["listener"].GetString() == "Company\\Shipping\\Listeners\\RecordShipment"));
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.UsesContract &&
            item.To.Key == queuedListenerKey && item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.Properties["queued"].GetBoolean());
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Name == "ConventionOnly");
        Assert.Equal(1, result.Diagnostics.Count(item => item.Code == "PHP_LARAVEL_EVENT_UNSUPPORTED"));
        Assert.Equal(2, result.Diagnostics.Count(item => item.Code == "PHP_LARAVEL_LISTENER_UNSUPPORTED"));
        foreach (var secret in new[] { "HELPER_EVENT_PAYLOAD_SECRET", "FACADE_EVENT_PAYLOAD_SECRET",
                     "STATIC_EVENT_PAYLOAD_SECRET", "STRING_HELPER_PAYLOAD_SECRET",
                     "STRING_FACADE_PAYLOAD_SECRET", "FACADE_LOOKALIKE_SECRET", "HELPER_LOOKALIKE_SECRET" })
            Assert.DoesNotContain(secret, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TypedKernelAndScheduleFacadeEmitBoundedTargetsAndCadenceWithoutOperationalData()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Shipping/Jobs/ScheduledShipment.php", """
            <?php
            namespace Company\Shipping\Jobs;
            use Illuminate\Contracts\Queue\ShouldQueue;
            final class ScheduledShipment implements ShouldQueue {}
            """);
        await repository.WriteAsync("src/Shipping/Jobs/PlainShipment.php", """
            <?php
            namespace Company\Shipping\Jobs;
            final class PlainShipment {}
            """);
        await repository.WriteAsync("src/Shipping/Tasks/ReconcileShipment.php", """
            <?php
            namespace Company\Shipping\Tasks;
            final class ReconcileShipment {
                public function run(): void {}
                public function __invoke(): void {}
            }
            """);
        await repository.WriteAsync("src/Billing/Console/Kernel.php", """
            <?php
            namespace Company\Billing\Console;
            use Company\Shipping\Jobs\PlainShipment;
            use Company\Shipping\Jobs\ScheduledShipment;
            use Company\Shipping\Tasks\ReconcileShipment;
            use Illuminate\Console\Scheduling\Schedule;
            use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
            final class Kernel extends ConsoleKernel {
                protected function schedule(Schedule $schedule): void {
                    $schedule->command('billing:close --token=COMMAND_ARGUMENT_SECRET')
                        ->cron('0 2 * * *')->timezone('UTC')->description('DESCRIPTION_SECRET')
                        ->withoutOverlapping(60);
                    $schedule->job(new ScheduledShipment('JOB_PAYLOAD_SECRET'))
                        ->everyTenSeconds()->onQueue('QUEUE_SECRET');
                    $schedule->call([ReconcileShipment::class, 'run'], ['CALL_ARGUMENT_SECRET'])->daily();
                    $schedule->call(new ReconcileShipment('INVOKABLE_SECRET'))->weekly();
                    $schedule->call(function (): void { $secret = 'CLOSURE_BODY_SECRET'; })
                        ->monthly()->when(fn () => 'CONDITION_SECRET');
                    $schedule->command($dynamic)->daily();
                    $schedule->command('billing:dynamic')->cron($dynamic);
                    $schedule->call([ReconcileShipment::class, 'missing'])->daily();
                    $schedule->job(new PlainShipment('PLAIN_JOB_SECRET'))->daily();
                }
            }
            """);
        await repository.WriteAsync("src/Billing/FacadeSchedules.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Tasks\ReconcileShipment;
            use Illuminate\Support\Facades\Schedule as Scheduler;
            final class FacadeSchedules {
                public function register(): void {
                    Scheduler::command('billing:facade --secret=FACADE_ARGUMENT_SECRET')->hourly();
                    Scheduler::call([ReconcileShipment::class, 'run'])->everyFiveMinutes();
                }
            }
            """);
        await repository.WriteAsync("src/Billing/ScheduleLookalike.php", """
            <?php
            namespace Company\Billing;
            use Acme\Schedule;
            final class ScheduleLookalike {
                public function register(): void {
                    Schedule::command('lookalike:secret LOOKALIKE_SECRET')->daily();
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var relationships = result.Observations.OfType<RelationshipObservation>().ToArray();
        var calls = relationships.Where(item => item.Relationship == EdgeKind.Calls &&
            item.Properties.ContainsKey("scheduled")).ToArray();
        var publishes = relationships.Where(item => item.Relationship == EdgeKind.Publishes &&
            item.Properties.ContainsKey("scheduled")).ToArray();
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-command:composer.json:billing:close" &&
            item.Properties["cadenceKind"].GetString() == "cron" &&
            item.Properties["cron"].GetString() == "0 2 * * *" &&
            item.Properties["timezone"].GetString() == "UTC");
        Assert.Contains(calls, item => item.To.Key == "php:laravel-command:composer.json:billing:facade" &&
            item.Properties["frequency"].GetString() == "hourly");
        Assert.Contains(calls, item => item.To.Key.Contains("ReconcileShipment::run", StringComparison.Ordinal) &&
            item.Properties["frequency"].GetString() == "daily");
        Assert.Contains(calls, item => item.To.Key.Contains("ReconcileShipment::__invoke", StringComparison.Ordinal) &&
            item.Properties["frequency"].GetString() == "weekly");
        Assert.Contains(calls, item => item.To.Key.StartsWith("php:scheduled-closure:", StringComparison.Ordinal) &&
            item.To.Resolution == Resolution.Unresolved && item.Properties["frequency"].GetString() == "monthly");
        Assert.Contains(publishes, item =>
            item.To.Key == "php:laravel-job:composer.json:Company\\Shipping\\Jobs\\ScheduledShipment" &&
            item.Properties["frequency"].GetString() == "everyTenSeconds" &&
            item.Properties["intervalSeconds"].GetInt32() == 10);
        Assert.Contains(calls, item => item.To.Key.Contains("ReconcileShipment::run", StringComparison.Ordinal) &&
            item.Properties["frequency"].GetString() == "everyFiveMinutes");
        Assert.Equal(2, calls.Count(item =>
            item.To.Key.Contains("ReconcileShipment::run", StringComparison.Ordinal)));
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(),
            item => item.Entity.Name == "lookalike:secret");
        Assert.Equal(4, result.Diagnostics.Count(item => item.Code == "PHP_LARAVEL_SCHEDULE_UNSUPPORTED"));
        foreach (var secret in new[] { "COMMAND_ARGUMENT_SECRET", "DESCRIPTION_SECRET", "JOB_PAYLOAD_SECRET",
                     "QUEUE_SECRET", "CALL_ARGUMENT_SECRET", "INVOKABLE_SECRET", "CLOSURE_BODY_SECRET",
                     "CONDITION_SECRET", "PLAIN_JOB_SECRET", "FACADE_ARGUMENT_SECRET", "LOOKALIKE_SECRET" })
            Assert.DoesNotContain(secret, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EloquentModelsEmitSafeDatabaseAndCrossModuleContractDependencies()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("src/Shipping/Models/Shipment.php", """
            <?php
            namespace Company\Shipping\Models;
            use Illuminate\Database\Eloquent\Model;
            final class Shipment extends Model {}
            """);
        await repository.WriteAsync("src/Billing/Models/BaseBillingModel.php", """
            <?php
            namespace Company\Billing\Models;
            use Illuminate\Database\Eloquent\Model;
            abstract class BaseBillingModel extends Model {}
            """);
        await repository.WriteAsync("src/Billing/Models/Customer.php", """
            <?php
            namespace Company\Billing\Models;
            final class Customer extends BaseBillingModel {}
            """);
        await repository.WriteAsync("src/Billing/Models/Invoice.php", """
            <?php
            namespace Company\Billing\Models;
            use Company\Shipping\Models\Shipment;
            final class Invoice extends BaseBillingModel {
                protected $connection = 'ledger';
                public function shipment() { return $this->belongsTo(Shipment::class, 'FOREIGN_KEY_SECRET'); }
                public function originalShipment() { return $this->belongsTo(Shipment::class); }
                public function customer() { return $this->hasMany(Customer::class, 'LOCAL_KEY_SECRET'); }
                public function dynamicShipment($dynamic) { return $this->belongsTo($dynamic); }
                public function subject() { return $this->morphTo(); }
                public function raw() { return DB::select('SELECT RAW_SQL_SECRET'); }
            }
            """);
        await repository.WriteAsync("src/Billing/Models/DynamicConnection.php", """
            <?php
            namespace Company\Billing\Models;
            final class DynamicConnection extends BaseBillingModel {
                protected $connection = self::CONNECTION_NAME;
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var entities = result.Observations.OfType<EntityObservation>().ToArray();
        var dependencies = result.Observations.OfType<RelationshipObservation>()
            .Where(item => item.Relationship == EdgeKind.DependsOn).ToArray();
        var ledgerKey = "php:laravel-database:composer.json:ledger";
        var defaultKey = "php:laravel-database:composer.json:default";
        var shipmentContractKey = "php:type:composer.json:Company\\Shipping\\Models\\Shipment";
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.Contains(entities, item => item.Entity.Key == ledgerKey &&
            item.Entity.Resolution == Resolution.Resolved && item.Evidence.Confidence == Confidence.Confirmed);
        Assert.Contains(entities, item => item.Entity.Key == defaultKey &&
            item.Entity.Resolution == Resolution.Unresolved && item.Evidence.Confidence == Confidence.Inferred);
        Assert.Contains(dependencies, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == ledgerKey &&
            item.Properties["model"].GetString() == "Company\\Billing\\Models\\Invoice" &&
            item.Properties["connection"].GetString() == "ledger");
        Assert.Contains(dependencies, item => item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.To.Key == defaultKey && item.Properties["default"].GetBoolean());
        Assert.Equal(2, dependencies.Count(item =>
            item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:module:composer.json:src/Shipping" &&
            item.Properties["relation"].GetString() == "belongsTo" &&
            item.Properties["usesContract"].GetString() == shipmentContractKey));
        Assert.Equal(2, entities.Count(item => item.Entity.Key == shipmentContractKey));
        Assert.DoesNotContain(dependencies, item =>
            item.Properties.TryGetValue("relatedModel", out var relatedModel) && relatedModel.GetString() ==
            "Company\\Billing\\Models\\Customer");
        Assert.DoesNotContain(dependencies, item =>
            item.Properties.TryGetValue("model", out var model) && model.GetString() ==
            "Company\\Billing\\Models\\DynamicConnection");
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ELOQUENT_CONNECTION_UNSUPPORTED");
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_LARAVEL_ELOQUENT_RELATION_UNSUPPORTED");
        foreach (var secret in new[] { "FOREIGN_KEY_SECRET", "LOCAL_KEY_SECRET", "RAW_SQL_SECRET" })
            Assert.DoesNotContain(secret, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InputAndSyntaxBudgetsFailClosedWithoutPartialObservations()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/limited", "autoload": { "psr-4": { "Limited\\": "src/" } } }
            """);
        await Write(temporary.Path, "src/One.php", "<?php\nfinal class One {}\n");

        var inputResult = await new PhpScanner(new(MaxInputFiles: 1))
            .ScanAsync(temporary.Path, CancellationToken.None);
        var syntaxResult = await new PhpScanner(new(MaxSyntaxNodesPerFile: 1))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.False(inputResult.Succeeded);
        Assert.Empty(inputResult.Observations);
        Assert.Contains(inputResult.Diagnostics, item => item.Code == "PHP_INPUT_LIMIT_EXCEEDED");
        Assert.False(syntaxResult.Succeeded);
        Assert.Empty(syntaxResult.Observations);
        Assert.Contains(syntaxResult.Diagnostics, item => item.Code == "PHP_SYNTAX_NODE_LIMIT_EXCEEDED" &&
            item.Message.Contains("per-file", StringComparison.Ordinal) &&
            item.Message.Contains("src/One.php", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LargeIrrelevantPhpTreeConsumesNoInputOrSyntaxBudgetAndChangesNoFindings()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", "{ \"name\": \"archie/focused-inputs\" }");
        var scanner = new PhpScanner(new(MaxInputFiles: 1, MaxInputBytes: 1024, MaxSyntaxNodesPerFile: 1, MaxSyntaxNodes: 1));
        var baseline = await scanner.ScanAsync(temporary.Path, CancellationToken.None);
        for (var index = 0; index < 100; index++)
            await Write(temporary.Path, $"legacy/generated/File{index:D3}.php",
                "<?php\n" + string.Concat(Enumerable.Repeat("function generated() { return 1; }\n", 100)));

        var result = await scanner.ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Equal(ContractJson.WriteObservationBundle(Bundle(baseline)),
            ContractJson.WriteObservationBundle(Bundle(result)));
    }

    [Fact]
    public async Task NestedProjectOwnershipPreventsParentPsr4RootFromAdmittingChildSource()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/parent", "autoload": { "psr-4": { "ParentApp\\": "src/" } } }
            """);
        await Write(temporary.Path, "src/ParentClass.php", "<?php\nnamespace ParentApp;\nfinal class ParentClass {}\n");
        await Write(temporary.Path, "src/child/composer.json", "{ \"name\": \"archie/child\" }");
        await WriteSparse(temporary.Path, "src/child/Irrelevant.php", 67_673_565);

        var result = await new PhpScanner(new(MaxInputFiles: 3))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Contains(result.SourceOwnership, item => item.Path == "src/ParentClass.php" &&
            item.OwnerCandidateKey == "php:composer-project:composer.json");
        Assert.DoesNotContain(result.SourceOwnership, item => item.Path.Contains("src/child/Irrelevant.php", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NestedProductionPackageBehaviorsUseTheEnclosingLaravelApplicationAndPackageOwner()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync("packages/Payments/composer.json", """
            { "name": "entorn/payments", "autoload": { "psr-4": { "Payments\\": "src/" } } }
            """);
        await repository.WriteAsync("packages/Payments/src/Http/PaymentController.php", """
            <?php
            namespace Payments\Http;
            final class PaymentController { public function show(): void {} }
            """);
        await repository.WriteAsync("packages/Payments/src/Routes/web.php", """
            <?php
            use Illuminate\Support\Facades\Route;
            use Payments\Http\PaymentController;
            Route::get('/payments', [PaymentController::class, 'show']);
            """);
        await repository.WriteAsync("packages/Payments/src/Jobs/SettlePayment.php", """
            <?php
            namespace Payments\Jobs;
            use Illuminate\Contracts\Queue\ShouldQueue;
            final class SettlePayment implements ShouldQueue {}
            """);
        await repository.WriteAsync("packages/Payments/src/PaymentWorkflow.php", """
            <?php
            namespace Payments;
            use Illuminate\Support\Facades\Http;
            use Payments\Jobs\SettlePayment;
            final class PaymentWorkflow {
                public function run(): void {
                    Http::post('https://payments.example.test/settle');
                    SettlePayment::dispatch();
                }
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var relationships = result.Observations.OfType<RelationshipObservation>().ToArray();
        const string owner = "php:composer-project:packages/Payments/composer.json";

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Contains && item.From.Key == owner &&
            item.To.Key == "php:http-endpoint:composer.json:GET:/payments");
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Calls && item.From.Key == owner &&
            item.To.Key == "php:external-service:https://payments.example.test");
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Publishes && item.From.Key == owner &&
            item.To.Key == "php:laravel-job:composer.json:Payments\\Jobs\\SettlePayment");
        Assert.Contains(result.SourceOwnership, item => item.Path == "packages/Payments/src/PaymentWorkflow.php" &&
            item.OwnerCandidateKey == owner && item.OwnershipKind == SourceOwnershipKind.Module);
    }

    [Fact]
    public async Task OverlappingProductionPsr4RootsAdmitEachSourceOnce()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            {
              "name": "archie/overlapping-roots",
              "autoload": { "psr-4": { "App\\": "src/", "Domain\\": "src/" } }
            }
            """);
        await Write(temporary.Path, "src/Thing.php", "<?php\nnamespace App;\nfinal class Thing {}\n");

        var result = await new PhpScanner(new(MaxInputFiles: 2))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Single(result.SourceOwnership, item => item.Path == "src/Thing.php");
    }

    [Fact]
    public async Task EligibleRouteFileStillFailsThePerFileSyntaxNodeBudget()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/route-limit", "require": { "laravel/framework": "^12.0" } }
            """);
        await Write(temporary.Path, "composer.lock", """
            { "packages": [{ "name": "laravel/framework", "version": "v12.0.0" }], "packages-dev": [] }
            """);
        await Write(temporary.Path, "artisan", "#!/usr/bin/env php\n<?php\n");
        await Write(temporary.Path, "bootstrap/app.php", "<?php\nreturn null;\n");
        await Write(temporary.Path, "app/Http/Marker.php", "<?php\n");
        await Write(temporary.Path, "routes/web.php", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/', fn () => null);\n");

        var result = await new PhpScanner(new(MaxSyntaxNodesPerFile: 1))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Contains(result.Diagnostics, item => item.Code == "PHP_SYNTAX_NODE_LIMIT_EXCEEDED" &&
            item.Message.Contains("per-file", StringComparison.Ordinal) &&
            item.Message.Contains("routes/web.php", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AggregateSyntaxNodeLimitIdentifiesTheEligibleFileAndCounts()
    {
        using var temporary = new TemporaryDirectory();
        const string firstSource = "<?php\nnamespace App;\nfinal class A {}\n";
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/aggregate-limit", "autoload": { "psr-4": { "App\\": "src/" } } }
            """);
        await Write(temporary.Path, "src/A.php", firstSource);
        await Write(temporary.Path, "src/B.php", "<?php\nnamespace App;\nfinal class B { public function run(): void {} }\n");
        using var syntax = new PhpSyntax();
        var measuredNodes = 0;
        var firstNodes = syntax.Validate(firstSource, new(), ref measuredNodes, CancellationToken.None).NodeCount;

        var result = await new PhpScanner(new(MaxSyntaxNodes: firstNodes + 1))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Contains(result.Diagnostics, item => item.Code == "PHP_SYNTAX_NODE_LIMIT_EXCEEDED" &&
            item.Message.Contains("aggregate", StringComparison.Ordinal) &&
            item.Message.Contains("src/B.php", StringComparison.Ordinal) &&
            item.Message.Contains($"{firstNodes} prior nodes", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TrackedOversizedBladeTemplateIsNotAnEligibleScannerInput()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", "{ \"name\": \"archie/tracked-blade-view\" }");
        await WriteSparse(temporary.Path, "resources/views/components/illustrations/notebook.blade.php", 67_673_565);

        var result = await new PhpScanner(new(MaxInputFiles: 1, MaxInputBytes: 1024))
            .ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
        Assert.Contains(result.Observations.OfType<EntityObservation>(), item =>
            item.Entity.Key == "php:composer-project:composer.json");
    }

    [Fact]
    public async Task SymlinkedDiscoveryConfigurationIsSkippedWithoutReadingItsTarget()
    {
        using var repository = new TestRepository();
        var marker = Path.Combine(repository.Path, "must-not-exist");
        await repository.WriteLaravelAsync(marker);
        var outside = Path.Combine(Path.GetTempPath(), $"archie-php-outside-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(outside, """
            { "schemaVersion": "php-discovery/v1", "modules": [{ "path": "src/Shipping", "name": "OUTSIDE_SECRET" }] }
            """);
        try
        {
            File.Delete(Path.Combine(repository.Path, ".archie/php-discovery.json"));
            File.CreateSymbolicLink(Path.Combine(repository.Path, ".archie/php-discovery.json"), outside);

            var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
            var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

            Assert.True(result.Succeeded);
            Assert.Contains(result.Diagnostics, item => item.Code == "PHP_SYMLINK_SKIPPED");
            Assert.DoesNotContain("OUTSIDE_SECRET", serialized, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public async Task InvalidUtf8SourceIsSkippedWithoutLeakingItsBytes()
    {
        using var repository = new TestRepository();
        await repository.WriteAsync("composer.json", """
            { "name": "entorn/encoding", "autoload": { "psr-4": { "Company\\": "src/" } } }
            """);
        var source = Path.Combine(repository.Path, "src/Poisoned.php");
        Directory.CreateDirectory(Path.GetDirectoryName(source)!);
        await File.WriteAllBytesAsync(source,
            [.. Encoding.UTF8.GetBytes("<?php // CONTENT_SECRET "), 0xFF, 0xFE]);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(result)));

        Assert.True(result.Succeeded);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_SOURCE_ENCODING_INVALID" &&
            item.Message.Contains("src/Poisoned.php", StringComparison.Ordinal));
        Assert.DoesNotContain("CONTENT_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(result.SourceOwnership, item => item.Path == "src/Poisoned.php");
    }

    [Fact]
    public async Task DiagnosticLimitFailsClosedWithoutPartialOutput()
    {
        using var repository = new TestRepository();
        await repository.WriteLaravelAsync(Path.Combine(repository.Path, "must-not-exist"));
        await repository.WriteAsync(".archie/php-discovery.json", """
            {
              "schemaVersion": "php-discovery/v1",
              "modules": [{ "path": "../one" }, { "path": "../two" }]
            }
            """);

        var result = await new PhpScanner(new(MaxDiagnostics: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_DIAGNOSTIC_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task NestedGitIgnoreRulesAndNegationSelectOnlyEligibleSource()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, ".gitignore", "generated/\n!generated/never-reincluded.php\n");
        await Write(temporary.Path, "composer.json", "{ \"name\": \"archie/nested-ignore\" }");
        await Write(temporary.Path, "src/.gitignore", "*.php\n!Keep.php\n");
        await Write(temporary.Path, "src/Keep.php", "<?php\nfinal class Keep {}\n");
        await WriteSparse(temporary.Path, "src/Discard.php", 67_673_565);
        await WriteSparse(temporary.Path, "generated/never-reincluded.php", 67_673_565);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Diagnostics.Select(item => item.Message)));
    }

    [Fact]
    public async Task EligibleOversizedPhpInputStillFailsTheWholeScan()
    {
        using var temporary = new TemporaryDirectory();
        await Write(temporary.Path, "composer.json", """
            { "name": "archie/oversized-source", "autoload": { "psr-4": { "App\\": "src/" } } }
            """);
        await WriteSparse(temporary.Path, "src/Oversized.php", 2 * 1024 * 1024 + 1);

        var result = await new PhpScanner().ScanAsync(temporary.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_INPUT_FILE_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task ScannerOutputIsByteDeterministic()
    {
        using var temporary = new TemporaryDirectory();
        await WriteLaravelProject(temporary.Path, Path.Combine(temporary.Path, "must-not-exist"));
        await Write(temporary.Path, "app/Models/Invoice.php", """
            <?php
            namespace App\Models;
            use Illuminate\Database\Eloquent\Model;
            final class Invoice extends Model { protected $connection = 'ledger'; }
            """);
        await Write(temporary.Path, "app/Jobs/SyncInvoice.php", """
            <?php
            namespace App\Jobs;
            use Illuminate\Contracts\Queue\ShouldQueue;
            final class SyncInvoice implements ShouldQueue {}
            """);
        await Write(temporary.Path, "app/Events/InvoiceCreated.php", """
            <?php
            namespace App\Events;
            final class InvoiceCreated {}
            """);
        await Write(temporary.Path, "app/Services/CheckoutWorkflow.php", """
            <?php
            namespace App\Services;
            use App\Events\InvoiceCreated;
            use App\Jobs\SyncInvoice;
            use Illuminate\Support\Facades\Http;
            final class CheckoutWorkflow {
                public function run(): void {
                    Http::get('https://payments.example.test/status');
                    SyncInvoice::dispatch();
                    event(new InvoiceCreated());
                }
            }
            """);
        await Write(temporary.Path, "routes/console.php", """
            <?php
            use Illuminate\Support\Facades\Schedule;
            Schedule::command('billing:close')->daily();
            """);
        var scanner = new PhpScanner();

        var first = await scanner.ScanAsync(temporary.Path, CancellationToken.None);
        var second = await scanner.ScanAsync(temporary.Path, CancellationToken.None);
        var firstBundle = Bundle(first);
        var secondBundle = Bundle(second);
        var extractionMethods = first.Observations.Select(item => item.Evidence.ExtractionMethod)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
        Assert.Contains("laravel:literal-controller-route", extractionMethods);
        Assert.Contains("laravel:http-literal-url", extractionMethods);
        Assert.Contains("laravel:queued-job-static-dispatch", extractionMethods);
        Assert.Contains("laravel:event-helper", extractionMethods);
        Assert.Contains("laravel:schedule-command", extractionMethods);
        Assert.Contains("laravel:eloquent-explicit-connection", extractionMethods);
        Assert.Equal(ContractJson.WriteObservationBundle(firstBundle), ContractJson.WriteObservationBundle(secondBundle));
    }

    [Fact]
    public async Task RealWorkerRejectsOversizedRequestWithStructuredDiagnosticAndZeroObservations()
    {
        var start = new ProcessStartInfo("dotnet", typeof(PhpScanner).Assembly.Location)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        using var process = Process.Start(start)!;
        var ready = await process.StandardOutput.ReadLineAsync();
        await process.StandardInput.WriteLineAsync(new string('x', PhpWorkerLimits.MaxRequestBytes + 1));
        process.StandardInput.Close();
        var diagnostic = await process.StandardOutput.ReadLineAsync();
        var completed = await process.StandardOutput.ReadLineAsync();
        await process.WaitForExitAsync();

        Assert.Contains("\"type\":\"ready\"", ready, StringComparison.Ordinal);
        Assert.Contains("PHP_WORKER_REQUEST_LIMIT_EXCEEDED", diagnostic, StringComparison.Ordinal);
        Assert.Contains("\"observationCount\":0", completed, StringComparison.Ordinal);
        Assert.Equal(0, process.ExitCode);
    }

    private static async Task WriteLaravelProject(string root, string marker)
    {
        await Write(root, "composer.json", """
            {
              "name": "archie/laravel-storefront",
              "require": { "php": "^8.3", "laravel/framework": "^12.0" },
              "autoload": { "psr-4": { "App\\": "app/" } }
            }
            """);
        await Write(root, "composer.lock", """
            { "packages": [{ "name": "laravel/framework", "version": "v12.0.0" }], "packages-dev": [] }
            """);
        await Write(root, "artisan", "#!/usr/bin/env php\n<?php\n");
        await Write(root, "bootstrap/app.php", "<?php\nreturn null;\n");
        await Write(root, "routes/web.php", "<?php\nuse App\\Http\\Controllers\\CheckoutController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/storefront/orders', [CheckoutController::class, 'store']);\n");
        await Write(root, "app/Http/Controllers/CheckoutController.php",
            $"<?php\nnamespace App\\Http\\Controllers;\nfile_put_contents('{marker.Replace("\\", "\\\\", StringComparison.Ordinal)}', 'executed');\nfinal class CheckoutController {{ public function store(): void {{}} }}\n");
    }

    private static Task Write(string root, string path, string content)
    {
        var fullPath = Path.Combine(root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        return File.WriteAllTextAsync(fullPath, content);
    }

    private static async Task WriteSparse(string root, string path, long length)
    {
        var fullPath = Path.Combine(root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await using var stream = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.SetLength(length);
    }

    private static ObservationBundle Bundle(PhpScanResult result) => new(
        "observations/v1", ObservationSource.Scanner, new string('a', 64),
        new("php-reference", null, "reference", false, new string('b', 64)),
        [new("archie.php", "2.0.0")], result.Observations, result.Diagnostics, []);

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"archie-php-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
