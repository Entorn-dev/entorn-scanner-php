using System.Text.Json;

namespace Archie.Scanner.Php.Tests;

internal sealed class TestRepository : IDisposable
{
    public TestRepository()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"archie-php-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public async Task WriteAsync(string relativePath, string content)
    {
        var fullPath = System.IO.Path.Combine(Path, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        await File.WriteAllTextAsync(fullPath, content);
    }

    public async Task WriteLaravelAsync(string marker)
    {
        await WriteAsync("composer.json", """
            {
              "name": "entorn/module-tracer",
              "require": { "laravel/framework": "^12.0", "psr/log": "^3.0" },
              "require-dev": { "phpunit/phpunit": "^12.0" },
              "autoload": { "psr-4": { "App\\": "app/", "Company\\": "src/" } }
            }
            """);
        await WriteAsync("composer.lock", """
            {
              "packages": [
                { "name": "laravel/framework", "version": "v12.0.0" },
                { "name": "psr/log", "version": "3.0.2" }
              ],
              "packages-dev": [{ "name": "phpunit/phpunit", "version": "12.0.0" }]
            }
            """);
        await WriteAsync("artisan", $"#!/usr/bin/env php\n<?php file_put_contents('{Escape(marker)}', 'ran');\n");
        await WriteAsync("bootstrap/app.php", "<?php return null;\n");
        await WriteAsync("app/Http/FrameworkMarker.php", "<?php namespace App\\Http; final class FrameworkMarker {}\n");
        await WriteAsync("src/Shipping/Domain/Shipment.php",
            "<?php namespace Company\\Shipping\\Domain; final class Shipment {}\n");
        await WriteAsync("src/Billing/CheckoutController.php", """
            <?php
            namespace Company\Billing;
            final class CheckoutController { public function store(): void {} }
            """);
        await WriteAsync("routes/web.php", """
            <?php
            use Company\Billing\CheckoutController;
            use Illuminate\Support\Facades\Route;
            Route::post('/checkout', [CheckoutController::class, 'store']);
            """);
        await WriteAsync(".archie/php-discovery.json", """
            {
              "schemaVersion": "php-discovery/v1",
              "modules": [{ "path": "src/Billing", "name": "Billing" }]
            }
            """);
    }

    public ScanRequestMessage Request() => new("scanner/v1", new(
        new("module-tracer", null, "main", false, new string('a', 64)), Path,
        JsonSerializer.SerializeToElement(new { })));

    public void Dispose() => Directory.Delete(Path, recursive: true);

    private static string Escape(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("'", "\\'", StringComparison.Ordinal);
}
