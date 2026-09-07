using Archie.Scanner.Php;
using Xunit;

namespace Archie.Scanner.Php.Tests;

public sealed class ObservationAssemblerTests
{
    [Fact]
    public async Task NestedMetadataOnlyComposerProjectDoesNotBecomeAModule()
    {
        using var repository = new TestRepository();
        await repository.WriteAsync("composer.json", """
            { "name": "entorn/root", "autoload": { "psr-4": { "Root\\": "src/" } } }
            """);
        await repository.WriteAsync("src/Root.php", "<?php namespace Root; final class Root {}\n");
        await repository.WriteAsync("tools/composer.json", "{ \"name\": \"entorn/tool\" }");

        var result = await new PhpScanner().ScanAsync(repository.Path, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Observations.OfType<EntityObservation>(),
            item => item.Entity.Key == "php:composer-project:tools/composer.json");
    }
}
