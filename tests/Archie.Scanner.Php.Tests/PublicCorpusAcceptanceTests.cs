using System.Text;
using System.Text.Json;
using Archie.Scanner.Php;
using Xunit;
using ContractJson = Entorn.Scanner.Contracts.ScannerContractJson;

namespace Archie.Scanner.Php.Tests;

public sealed class PublicCorpusAcceptanceTests
{
    private const string CheckoutVariable = "ENTORN_BAGISTO_CHECKOUT";
    private const string ExpectedRevision = "aa544167182b3503c08a3b27981288d1921fbf4d";

    [Fact]
    public async Task PinnedBagistoCorpusMatchesReviewedStaticManifestAndIsDeterministic()
    {
        var checkout = Environment.GetEnvironmentVariable(CheckoutVariable);
        if (string.IsNullOrWhiteSpace(checkout))
        {
            Console.WriteLine($"SKIPPED: Set {CheckoutVariable} through scripts/test-acceptance.sh to scan pinned Bagisto.");
            return;
        }

        using var manifest = JsonDocument.Parse(await File.ReadAllBytesAsync(
            Path.Combine(AppContext.BaseDirectory, "acceptance", "bagisto-aa544167.json")));
        Assert.Equal("php-public-corpus/v1", manifest.RootElement.GetProperty("schemaVersion").GetString());
        Assert.Equal(ExpectedRevision, manifest.RootElement.GetProperty("revision").GetString());

        var scanner = new PhpScanner();
        var first = await scanner.ScanAsync(checkout, CancellationToken.None);
        var second = await scanner.ScanAsync(checkout, CancellationToken.None);

        Assert.True(first.Succeeded, string.Join(Environment.NewLine,
            first.Diagnostics.Select(item => $"{item.Code}: {item.Message}")));
        Assert.True(second.Succeeded);
        Assert.Equal(ContractJson.WriteObservationBundle(Bundle(first)),
            ContractJson.WriteObservationBundle(Bundle(second)));

        foreach (var expected in manifest.RootElement.GetProperty("entities").EnumerateArray())
        {
            var key = expected.GetProperty("key").GetString()!;
            var path = expected.GetProperty("path").GetString()!;
            var rule = expected.GetProperty("rule").GetString()!;
            Assert.True(first.Observations.OfType<EntityObservation>().Any(item =>
                    item.Entity.Key == key && item.Evidence.Path == path && item.Evidence.ExtractionMethod == rule),
                $"Bagisto entity '{key}' with {path} / {rule} was not discovered.");
        }

        foreach (var expected in manifest.RootElement.GetProperty("relationships").EnumerateArray())
        {
            var relationship = Relationship(expected.GetProperty("relationship").GetString()!);
            var from = expected.GetProperty("from").GetString()!;
            var to = expected.GetProperty("to").GetString()!;
            var path = expected.GetProperty("path").GetString()!;
            var rule = expected.GetProperty("rule").GetString()!;
            Assert.True(first.Observations.OfType<RelationshipObservation>().Any(item =>
                    item.Relationship == relationship && item.From.Key == from && item.To.Key == to &&
                    item.Evidence.Path == path && item.Evidence.ExtractionMethod == rule),
                $"Bagisto relationship '{relationship}' from '{from}' to '{to}' with {path} / {rule} was not discovered.");
        }

        foreach (var gap in manifest.RootElement.GetProperty("knownStaticGaps").EnumerateArray())
        {
            var path = Path.Combine(checkout, gap.GetProperty("path").GetString()!.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(path), $"Reviewed Bagisto static-gap source '{path}' no longer exists.");
        }

        var serialized = Encoding.UTF8.GetString(ContractJson.WriteObservationBundle(Bundle(first)));
        Assert.DoesNotContain("client_secret", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("access_token", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(checkout, serialized, StringComparison.Ordinal);
    }

    private static EdgeKind Relationship(string value) => value switch
    {
        "contains" => EdgeKind.Contains,
        "depends-on" => EdgeKind.DependsOn,
        "publishes" => EdgeKind.Publishes,
        "subscribes" => EdgeKind.Subscribes,
        _ => throw new InvalidDataException($"Unsupported acceptance relationship '{value}'.")
    };

    private static ObservationBundle Bundle(PhpScanResult result) => new(
        "observations/v1", ObservationSource.Scanner, new string('a', 64),
        new("bagisto", null, ExpectedRevision, false, new string('b', 64)),
        [new("archie.php", "2.0.0")], result.Observations, result.Diagnostics, []);
}
