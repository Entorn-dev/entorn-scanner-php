using System.Diagnostics;
using System.Text.Json;
using Archie.Scanner.Php;
using Xunit;

namespace Archie.Scanner.Php.Tests;

public sealed class LaravelBoundaryDiscoveryTests
{
    [Fact]
    public async Task ConfiguredAndConventionalModulesFlowThroughTheRealWorker()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);

        var direct = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        Assert.True(direct.Succeeded, string.Join(Environment.NewLine, direct.Diagnostics.Select(item => item.Message)));
        foreach (var observation in direct.Observations)
            JsonSerializer.Serialize<ProtocolMessage>(new ObservationMessage("scanner/v1", observation),
                ScannerContractJson.Options);
        foreach (var item in direct.SourceOwnership)
            JsonSerializer.Serialize<ProtocolMessage>(new SourceOwnershipMessage("scanner/v1", item),
                ScannerContractJson.Options);
        var messages = await RunWorker(repository.Request());
        var observations = messages.OfType<ObservationMessage>().Select(item => item.Observation).ToArray();
        var ownership = messages.OfType<SourceOwnershipMessage>().Select(item => item.Ownership).ToArray();
        var entities = observations.OfType<EntityObservation>().ToArray();
        var relationships = observations.OfType<RelationshipObservation>().ToArray();

        Assert.False(File.Exists(marker));
        Assert.IsType<ReadyMessage>(messages[0]);
        var completed = Assert.IsType<CompletedMessage>(messages[^1]);
        Assert.Equal(observations.Length, completed.Summary.ObservationCount);
        Assert.DoesNotContain(entities, item => item.Entity.Key == "php:composer-project:composer.json");
        Assert.Contains(entities, item => item.Entity.Key == "php:laravel-app:composer.json" &&
            item.Entity.Kind == NodeKind.Deployable);
        Assert.Contains(entities, item => item.Entity.Key == "php:module:composer.json:src/Shipping" &&
            item.Entity.Name == "Shipping");
        Assert.Contains(entities, item => item.Entity.Key == "php:module:composer.json:src/Billing" &&
            item.Entity.Name == "Billing" && item.Evidence.Confidence == Confidence.Confirmed &&
            item.Evidence.Path == ".archie/php-discovery.json");
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Contains &&
            item.From.Key == "php:laravel-app:composer.json" &&
            item.To.Key == "php:module:composer.json:src/Billing");
        Assert.Contains(relationships, item => item.Relationship == EdgeKind.Contains &&
            item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:http-endpoint:composer.json:POST:/checkout");
        Assert.Contains(ownership, item => item.Path == "src/Shipping/Domain/Shipment.php" &&
            item.OwnerCandidateKey == "php:module:composer.json:src/Shipping" &&
            item.OwnershipKind == SourceOwnershipKind.Module);
        Assert.Contains(ownership, item => item.Path == "src/Billing/CheckoutController.php" &&
            item.OwnerCandidateKey == "php:module:composer.json:src/Billing" &&
            item.OwnershipKind == SourceOwnershipKind.Module);
        Assert.Contains(ownership, item => item.Path == "app/Http/FrameworkMarker.php" &&
            item.OwnerCandidateKey == "php:laravel-app:composer.json" &&
            item.OwnershipKind == SourceOwnershipKind.Deployable);
        Assert.Contains(ownership, item => item.Path == "routes/web.php" &&
            item.OwnerCandidateKey == "php:laravel-app:composer.json" &&
            item.OwnershipKind == SourceOwnershipKind.Deployable);
        Assert.DoesNotContain(entities, item => item.Entity.Key == "php:composer-package:phpunit/phpunit");
        Assert.All(observations, item => Assert.Equal("archie.php", item.Evidence.ScannerId));
    }

    [Fact]
    public async Task SupportedRouteFamiliesFlowThroughTheRealWorkerWithoutExecutingTargetPhp()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);
        await repository.WriteAsync("composer.json", """
            {
              "name": "entorn/module-tracer",
              "require": {
                "laravel/framework": "^12.0",
                "psr/log": "^3.0",
                "spatie/laravel-route-attributes": "^1.0"
              },
              "autoload": { "psr-4": { "App\\": "app/", "Company\\": "src/" } }
            }
            """);
        await repository.WriteAsync("composer.lock", """
            {
              "packages": [
                { "name": "laravel/framework", "version": "v12.0.0" },
                { "name": "psr/log", "version": "3.0.2" },
                { "name": "spatie/laravel-route-attributes", "version": "1.27.0" }
              ],
              "packages-dev": []
            }
            """);
        await repository.WriteAsync("src/Billing/CheckoutController.php", """
            <?php
            namespace Company\Billing;
            final class CheckoutController {
                public function __invoke(): void {}
                public function index(): void {}
                public function create(): void {}
                public function store(): void {}
                public function show(): void {}
                public function edit(): void {}
                public function update(): void {}
                public function destroy(): void {}
            }
            """);
        await repository.WriteAsync("routes/web.php", """
            <?php
            use Company\Billing\CheckoutController;
            use Illuminate\Support\Facades\Route;
            Route::head('/health', fn () => null);
            Route::match(['get', 'post'], '/search', [CheckoutController::class, 'index']);
            Route::any('/hook', CheckoutController::class);
            Route::resource('orders', CheckoutController::class);
            Route::apiResource('customers', CheckoutController::class);
            Route::prefix('api')->domain('store.example.test')->name('api.')->controller(CheckoutController::class)->group(function () {
                Route::get('orders', 'index')->name('orders');
            });
            Route::get('/legacy', 'Company\Billing\CheckoutController@show');
            Route::get($dynamic, fn () => null);
            """);
        await repository.WriteAsync("src/Billing/AttributedController.php", """
            <?php
            namespace Company\Billing;
            use Spatie\RouteAttributes\Attributes\Domain;
            use Spatie\RouteAttributes\Attributes\Get;
            use Spatie\RouteAttributes\Attributes\Prefix;
            #[Prefix('attribute-api')]
            #[Domain('attribute.example.test')]
            final class AttributedController {
                #[Get('orders', name: 'attribute.orders')]
                public function index(): void {}
            }
            """);
        await repository.WriteAsync("src/Billing/PaymentGateway.php", """
            <?php
            namespace Company\Billing;
            use Illuminate\Support\Facades\Http;
            final class PaymentGateway {
                public function charge(): void {
                    Http::post('https://payments.example.test/charges?token=QUERY_SECRET',
                        ['card' => 'BODY_SECRET']);
                    Http::baseUrl('https://shipping.example.test/v1')
                        ->withToken('TOKEN_SECRET')->get('/quotes');
                }
            }
            """);
        await repository.WriteAsync("src/Shipping/Contracts/QueuedWork.php", """
            <?php
            namespace Company\Shipping\Contracts;
            use Illuminate\Contracts\Queue\ShouldQueue;
            interface QueuedWork extends ShouldQueue {}
            """);
        await repository.WriteAsync("src/Shipping/Jobs/SyncShipment.php", """
            <?php
            namespace Company\Shipping\Jobs;
            use Company\Shipping\Contracts\QueuedWork;
            final class SyncShipment implements QueuedWork {}
            """);
        await repository.WriteAsync("src/Billing/JobDispatcher.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Jobs\SyncShipment;
            use Illuminate\Support\Facades\Bus;
            final class JobDispatcher {
                public function dispatch(): void {
                    Bus::dispatch(new SyncShipment('JOB_PAYLOAD_SECRET'));
                }
            }
            """);
        await repository.WriteAsync("src/Shipping/Events/ShipmentCreated.php", """
            <?php
            namespace Company\Shipping\Events;
            use Illuminate\Foundation\Events\Dispatchable;
            final class ShipmentCreated { use Dispatchable; }
            """);
        await repository.WriteAsync("src/Shipping/Listeners/NotifyWarehouse.php", """
            <?php
            namespace Company\Shipping\Listeners;
            use Illuminate\Contracts\Queue\ShouldQueue;
            final class NotifyWarehouse implements ShouldQueue { public function handle(): void {} }
            """);
        await repository.WriteAsync("src/Billing/EventPublisher.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Illuminate\Support\Facades\Event;
            final class EventPublisher {
                public function publish(): void {
                    Event::dispatch(new ShipmentCreated('EVENT_PAYLOAD_SECRET'));
                    event('shipment.created', ['token' => 'STRING_EVENT_PAYLOAD_SECRET']);
                }
            }
            """);
        await repository.WriteAsync("src/Billing/EventServiceProvider.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Events\ShipmentCreated;
            use Company\Shipping\Listeners\NotifyWarehouse;
            use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
            final class EventServiceProvider extends ServiceProvider {
                protected $listen = [
                    ShipmentCreated::class => [NotifyWarehouse::class],
                    'shipment.created' => [NotifyWarehouse::class],
                ];
            }
            """);
        await repository.WriteAsync("src/Billing/FacadeSchedules.php", """
            <?php
            namespace Company\Billing;
            use Company\Shipping\Jobs\SyncShipment;
            use Illuminate\Support\Facades\Schedule;
            final class FacadeSchedules {
                public function register(): void {
                    Schedule::command('billing:close --token=SCHEDULE_COMMAND_SECRET')
                        ->cron('0 2 * * *')->timezone('UTC');
                    Schedule::job(new SyncShipment('SCHEDULE_JOB_SECRET'))->everyThirtySeconds();
                    Schedule::call([CheckoutController::class, 'index'])->daily();
                    Schedule::call(fn () => 'SCHEDULE_CLOSURE_SECRET')->weekly();
                }
            }
            """);
        await repository.WriteAsync("src/Shipping/Models/ShipmentRecord.php", """
            <?php
            namespace Company\Shipping\Models;
            use Illuminate\Database\Eloquent\Model;
            final class ShipmentRecord extends Model {}
            """);
        await repository.WriteAsync("src/Billing/Models/Invoice.php", """
            <?php
            namespace Company\Billing\Models;
            use Company\Shipping\Models\ShipmentRecord;
            use Illuminate\Database\Eloquent\Model;
            final class Invoice extends Model {
                protected $connection = 'ledger';
                public function shipment() {
                    return $this->belongsTo(ShipmentRecord::class, 'ELOQUENT_KEY_SECRET');
                }
            }
            """);

        var messages = await RunWorker(repository.Request());
        var endpoints = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<EntityObservation>().Where(item => item.Entity.Kind == NodeKind.HttpEndpoint).ToArray();
        var calls = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<RelationshipObservation>().Where(item => item.Relationship == EdgeKind.Calls).ToArray();
        var publishes = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<RelationshipObservation>().Where(item => item.Relationship == EdgeKind.Publishes).ToArray();
        var contracts = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<RelationshipObservation>().Where(item => item.Relationship == EdgeKind.UsesContract).ToArray();
        var subscriptions = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<RelationshipObservation>().Where(item => item.Relationship == EdgeKind.Subscribes).ToArray();
        var dependencies = messages.OfType<ObservationMessage>().Select(item => item.Observation)
            .OfType<RelationshipObservation>().Where(item => item.Relationship == EdgeKind.DependsOn).ToArray();
        var serialized = JsonSerializer.Serialize(messages, ScannerContractJson.Options);

        Assert.False(File.Exists(marker));
        Assert.Contains(endpoints, item => item.Entity.Name == "HEAD /health");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /search");
        Assert.Contains(endpoints, item => item.Entity.Name == "DELETE /hook");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /orders/{order}/edit");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /customers/{customer}");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /api/orders" &&
            item.Entity.Properties["domain"].GetString() == "store.example.test" &&
            item.Entity.Properties["routeName"].GetString() == "api.orders");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /legacy");
        Assert.Contains(endpoints, item => item.Entity.Name == "GET /attribute-api/orders" &&
            item.Entity.Properties["domain"].GetString() == "attribute.example.test" &&
            item.Evidence.Confidence == Confidence.Inferred);
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:external-service:https://payments.example.test");
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:external-service:https://shipping.example.test");
        Assert.Contains(publishes, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-job:composer.json:Company\\Shipping\\Jobs\\SyncShipment");
        Assert.Contains(contracts, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:type:composer.json:Company\\Shipping\\Jobs\\SyncShipment");
        Assert.Contains(publishes, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-event:composer.json:class:Company\\Shipping\\Events\\ShipmentCreated");
        Assert.Contains(publishes, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-event:composer.json:name:shipment.created");
        Assert.Contains(subscriptions, item =>
            item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.To.Key == "php:laravel-event:composer.json:class:Company\\Shipping\\Events\\ShipmentCreated" &&
            item.Properties["listener"].GetString() == "Company\\Shipping\\Listeners\\NotifyWarehouse" &&
            item.Properties["queued"].GetBoolean());
        Assert.Contains(subscriptions, item =>
            item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.To.Key == "php:laravel-event:composer.json:name:shipment.created" &&
            item.Properties["queued"].GetBoolean());
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-command:composer.json:billing:close" &&
            item.Properties["cron"].GetString() == "0 2 * * *" &&
            item.Properties["timezone"].GetString() == "UTC");
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key.Contains("CheckoutController::index", StringComparison.Ordinal) &&
            item.Properties["frequency"].GetString() == "daily");
        Assert.Contains(calls, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key.StartsWith("php:scheduled-closure:", StringComparison.Ordinal) &&
            item.Properties["frequency"].GetString() == "weekly");
        Assert.Contains(publishes, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-job:composer.json:Company\\Shipping\\Jobs\\SyncShipment" &&
            item.Properties.ContainsKey("scheduled") &&
            item.Properties["intervalSeconds"].GetInt32() == 30);
        Assert.Contains(dependencies, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:laravel-database:composer.json:ledger" &&
            item.Properties["model"].GetString() == "Company\\Billing\\Models\\Invoice");
        Assert.Contains(dependencies, item => item.From.Key == "php:module:composer.json:src/Shipping" &&
            item.To.Key == "php:laravel-database:composer.json:default" &&
            item.To.Resolution == Resolution.Unresolved);
        Assert.Contains(dependencies, item => item.From.Key == "php:module:composer.json:src/Billing" &&
            item.To.Key == "php:module:composer.json:src/Shipping" &&
            item.Properties["usesContract"].GetString() ==
            "php:type:composer.json:Company\\Shipping\\Models\\ShipmentRecord");
        Assert.DoesNotContain("QUERY_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("BODY_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("TOKEN_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("JOB_PAYLOAD_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("EVENT_PAYLOAD_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("STRING_EVENT_PAYLOAD_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("SCHEDULE_COMMAND_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("SCHEDULE_JOB_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("SCHEDULE_CLOSURE_SECRET", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("ELOQUENT_KEY_SECRET", serialized, StringComparison.Ordinal);
        Assert.Single(messages.OfType<DiagnosticMessage>(), item =>
            item.Diagnostic.Code == "PHP_LARAVEL_ROUTE_UNSUPPORTED");
        Assert.IsType<CompletedMessage>(messages[^1]);
    }

    [Fact]
    public async Task ConfigurationCannotDeclareAPathOutsideProductionSource()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);
        await repository.WriteAsync(".archie/php-discovery.json", """
            { "schemaVersion": "php-discovery/v1", "modules": [{ "path": "routes", "name": "Routes" }] }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Diagnostics, item => item.Code == "PHP_DISCOVERY_MODULE_OUTSIDE_PRODUCTION_SOURCE");
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(),
            item => item.Entity.Key == "php:module:composer.json:routes");
    }

    [Fact]
    public async Task ConfigurationConfirmsConventionWithoutDiscardingItsEvidence()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);
        await repository.WriteAsync(".archie/php-discovery.json", """
            {
              "schemaVersion": "php-discovery/v1",
              "modules": [{ "path": "src/Shipping", "name": "Logistics" }]
            }
            """);

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);
        var moduleEvidence = result.Observations.OfType<EntityObservation>()
            .Where(item => item.Entity.Key == "php:module:composer.json:src/Shipping").ToArray();

        Assert.True(result.Succeeded);
        Assert.Equal(2, moduleEvidence.Length);
        Assert.All(moduleEvidence, item => Assert.Equal("Logistics", item.Entity.Name));
        Assert.Contains(moduleEvidence, item => item.Evidence.Path == ".archie/php-discovery.json" &&
            item.Evidence.Confidence == Confidence.Confirmed);
        Assert.Contains(moduleEvidence, item => item.Evidence.Path == "src/Shipping/Domain/Shipment.php" &&
            item.Evidence.Confidence == Confidence.Inferred);
        Assert.Single(moduleEvidence.Select(item => item.Entity.Key).Distinct(StringComparer.Ordinal));
        Assert.Equal(2, moduleEvidence.Select(item => item.Id).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task ConfiguredModuleLimitFailsWithoutPartialOutput()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);
        await repository.WriteAsync(".archie/php-discovery.json", """
            {
              "schemaVersion": "php-discovery/v1",
              "modules": [{ "path": "src/Billing" }, { "path": "src/Shipping" }]
            }
            """);

        var result = await new PhpScanner(new(MaxConfiguredModules: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_CONFIGURED_MODULE_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task ConfiguredModuleBudgetIsSharedAcrossLaravelProjects()
    {
        using var repository = new TestRepository();
        await WriteNestedLaravel(repository, "one");
        await WriteNestedLaravel(repository, "two");

        var result = await new PhpScanner(new(MaxConfiguredModules: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_CONFIGURED_MODULE_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task OversizedConfigurationUsesTheExistingFailClosedInputBudget()
    {
        using var repository = new TestRepository();
        var marker = System.IO.Path.Combine(repository.Path, "target-code-ran");
        await repository.WriteLaravelAsync(marker);

        var result = await new PhpScanner(new(MaxDiscoveryConfigurationBytes: 32))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_INPUT_FILE_LIMIT_EXCEEDED" &&
            item.Message.Contains("php-discovery.json", StringComparison.Ordinal));
    }

    private static async Task<IReadOnlyList<ProtocolMessage>> RunWorker(ScanRequestMessage request)
    {
        var start = new ProcessStartInfo(
            Environment.ProcessPath!, typeof(PhpScanner).Assembly.Location)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        using var process = Process.Start(start)!;
        var json = new JsonSerializerOptions(ScannerContractJson.Options) { WriteIndented = false };
        var requestJson = JsonSerializer.Serialize<ProtocolMessage>(request, json);
        Assert.IsType<ScanRequestMessage>(
            JsonSerializer.Deserialize<ProtocolMessage>(requestJson, json));
        await process.StandardInput.WriteLineAsync(requestJson);
        process.StandardInput.Close();
        var messages = new List<ProtocolMessage>();
        string? line;
        while ((line = await process.StandardOutput.ReadLineAsync()) is not null)
            messages.Add(JsonSerializer.Deserialize<ProtocolMessage>(line, json)!);
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.Equal(0, process.ExitCode);
        Assert.True(string.IsNullOrEmpty(error), error + Environment.NewLine + requestJson + Environment.NewLine +
            string.Join(Environment.NewLine,
            messages.Select(item => item is DiagnosticMessage diagnostic
                ? $"{item.GetType().Name}: {diagnostic.Diagnostic.Code} {diagnostic.Diagnostic.Message}"
                : item.GetType().Name)));
        return messages;
    }

    private static async Task WriteNestedLaravel(TestRepository repository, string root)
    {
        await repository.WriteAsync($"{root}/composer.json", $$"""
            {
              "name": "entorn/{{root}}",
              "require": { "laravel/framework": "^12.0" },
              "autoload": { "psr-4": { "App\\": "app/" } }
            }
            """);
        await repository.WriteAsync($"{root}/composer.lock", """
            { "packages": [{ "name": "laravel/framework", "version": "v12.0.0" }], "packages-dev": [] }
            """);
        await repository.WriteAsync($"{root}/artisan", "#!/usr/bin/env php\n<?php\n");
        await repository.WriteAsync($"{root}/bootstrap/app.php", "<?php return null;\n");
        await repository.WriteAsync($"{root}/routes/web.php", "<?php\n");
        await repository.WriteAsync($"{root}/app/Http/Marker.php", "<?php namespace App\\Http; final class Marker {}\n");
        await repository.WriteAsync($"{root}/.archie/php-discovery.json", """
            { "schemaVersion": "php-discovery/v1", "modules": [{ "path": "app/Http" }] }
            """);
    }
}
