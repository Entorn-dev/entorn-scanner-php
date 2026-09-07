using Archie.Scanner.Php;
using Xunit;

namespace Archie.Scanner.Php.Tests;

public sealed class PhpSyntaxTests
{
    [Fact]
    public async Task ApplicationIndexGroupsPsr4DeclarationsByRepositoryPath()
    {
        using var repository = new TestRepository();
        await repository.WriteAsync("composer.json", """
            { "name": "entorn/index", "autoload": { "psr-4": { "Company\\": "src/" } } }
            """);
        await repository.WriteAsync("src/Shipping/Domain/Shipment.php", """
            <?php
            namespace Company\Shipping\Domain;
            final class Shipment { public function send(): void {} }
            """);

        using var model = await new PhpRepositoryModelBuilder(new()).BuildAsync(
            repository.Path, CancellationToken.None);

        var project = Assert.Single(model.Projects);
        var declaration = Assert.Single(project.Index.TypesByPath["src/Shipping/Domain/Shipment.php"]);
        Assert.Equal("Company\\Shipping\\Domain\\Shipment", declaration.FullyQualifiedName);
        Assert.Contains("send", declaration.Methods);
    }

    [Fact]
    public async Task AggregateSymbolLimitFailsClosed()
    {
        using var repository = new TestRepository();
        await repository.WriteAsync("composer.json", """
            { "name": "entorn/index", "autoload": { "psr-4": { "Company\\": "src/" } } }
            """);
        await repository.WriteAsync("src/One.php", "<?php namespace Company; final class One {}\n");
        await repository.WriteAsync("src/Two.php", "<?php namespace Company; final class Two {}\n");

        var result = await new PhpScanner(new(MaxSymbols: 1)).ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_SYMBOL_LIMIT_EXCEEDED");
    }

    [Fact]
    public async Task AggregateStaticReferenceLimitFailsClosed()
    {
        using var repository = new TestRepository();
        await repository.WriteAsync("composer.json", """
            { "name": "entorn/index", "autoload": { "psr-4": { "Company\\": "src/" } } }
            """);
        await repository.WriteAsync("src/One.php", """
            <?php
            namespace Company;
            use Vendor\BaseClass;
            use Vendor\SomeTrait;
            final class One extends BaseClass { use SomeTrait; }
            """);

        var result = await new PhpScanner(new(MaxReferences: 1))
            .ScanAsync(repository.Path, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.Observations);
        Assert.Empty(result.SourceOwnership);
        Assert.Single(result.Diagnostics, item => item.Code == "PHP_REFERENCE_LIMIT_EXCEEDED");
    }
}
