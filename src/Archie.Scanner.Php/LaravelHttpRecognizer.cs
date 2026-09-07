using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelHttpRecognizer
{
    private const string HttpFacade = "Illuminate\\Support\\Facades\\Http";
    private static readonly IReadOnlySet<string> Terminals = new HashSet<string>(
        ["get", "post", "put", "patch", "delete", "head", "send"], StringComparer.OrdinalIgnoreCase);
    private static readonly IReadOnlySet<string> FluentModifiers = new HashSet<string>(
    [
        "accept", "acceptJson", "asForm", "asJson", "attach", "beforeSending", "connectTimeout",
        "retry", "timeout", "withBasicAuth", "withBody", "withCookies", "withDigestAuth",
        "withHeader", "withHeaders", "withOptions", "withToken", "withoutRedirecting",
        "withoutVerifying"
    ], StringComparer.OrdinalIgnoreCase);

    public static LaravelHttpScanResult Scan(PhpProjectModel project, CancellationToken cancellationToken)
    {
        var detections = new List<LaravelHttpDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var call in document.CleanDescendants("scoped_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scope = call.GetChildForField("scope");
                var terminal = call.GetChildForField("name")?.Text;
                if (scope is null || terminal is null || !Terminals.Contains(terminal) ||
                    !string.Equals(document.ResolveClassName(scope), HttpFacade, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!TryReadArguments(call, out var arguments) ||
                    !TryReadTarget(document, terminal, arguments, out var target) ||
                    !TryNormalizeAbsoluteOrigin(target, out var origin))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }
                detections.Add(Detection(origin, document, call, "laravel:http-literal-url"));
            }

            foreach (var terminalCall in document.CleanDescendants("member_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var terminal = terminalCall.GetChildForField("name")?.Text;
                if (terminal is null || !Terminals.Contains(terminal) ||
                    !TryReadFluentChain(document, terminalCall, out var chain) || !chain.IsHttpFacade)
                    continue;
                if (!chain.RootName.Equals("baseUrl", StringComparison.OrdinalIgnoreCase) ||
                    chain.Modifiers.Any(item => !FluentModifiers.Contains(item)) ||
                    FindArgument(chain.RootArguments, "url", 0) is not { } baseExpression ||
                    document.Literal(baseExpression) is not { } baseUrl ||
                    !TryReadArguments(terminalCall, out var terminalArguments) ||
                    !TryReadTarget(document, terminal, terminalArguments, out var relativeTarget) ||
                    !TryJoinOrigin(baseUrl, relativeTarget, out var origin))
                {
                    diagnostics.Add(Unsupported(project, document, terminalCall));
                    continue;
                }
                detections.Add(Detection(origin, document, terminalCall, "laravel:http-literal-base-url"));
            }
        }

        return new(
            detections.OrderBy(item => item.Origin, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.Range.StartLine).ThenBy(item => item.Range.StartColumn).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static bool TryReadFluentChain(PhpDocument document, Node terminal, out FluentChain chain)
    {
        var modifiers = new List<string>();
        var expression = terminal.GetChildForField("object");
        while (expression?.Type == "member_call_expression")
        {
            var name = expression.GetChildForField("name")?.Text;
            if (name is null) { chain = default!; return false; }
            modifiers.Add(name);
            expression = expression.GetChildForField("object");
        }
        modifiers.Reverse();
        if (expression?.Type != "scoped_call_expression" ||
            expression.GetChildForField("scope") is not { } scope ||
            expression.GetChildForField("name")?.Text is not { } rootName ||
            !TryReadArguments(expression, out var rootArguments))
        {
            chain = default!;
            return false;
        }
        chain = new(string.Equals(document.ResolveClassName(scope), HttpFacade, StringComparison.OrdinalIgnoreCase),
            rootName, rootArguments, modifiers);
        return true;
    }

    private static bool TryReadTarget(PhpDocument document, string terminal,
        IReadOnlyList<CallArgument> arguments, out string target)
    {
        target = string.Empty;
        var position = terminal.Equals("send", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        var expression = FindArgument(arguments, "url", position);
        if (expression is null || document.Literal(expression) is not { } literal || !IsSafe(literal)) return false;
        target = literal;
        return true;
    }

    private static bool TryReadArguments(Node call, out IReadOnlyList<CallArgument> arguments)
    {
        var container = call.GetChildForField("arguments");
        if (container is null) { arguments = []; return false; }
        var result = new List<CallArgument>();
        foreach (var argument in container.NamedChildren)
        {
            if (argument.Type != "argument" || argument.NamedChildren.Count is < 1 or > 2)
            {
                arguments = [];
                return false;
            }
            var name = argument.NamedChildren.Count == 2 ? argument.NamedChildren[0].Text : null;
            result.Add(new(name, argument.NamedChildren[^1]));
        }
        arguments = result;
        return true;
    }

    private static Node? FindArgument(IReadOnlyList<CallArgument> arguments, string name, int position) =>
        arguments.FirstOrDefault(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))?.Value ??
        (position < arguments.Count && arguments[position].Name is null ? arguments[position].Value : null);

    private static bool TryJoinOrigin(string baseUrl, string relativeTarget, out NormalizedOrigin origin)
    {
        origin = default!;
        if (!IsSafe(baseUrl) || !IsSafe(relativeTarget) || relativeTarget.StartsWith("//", StringComparison.Ordinal) ||
            HasScheme(relativeTarget)) return false;
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri) ||
            !TryNormalizeAbsoluteOrigin(baseUrl, out _) || !Uri.TryCreate(baseUri, relativeTarget, out var joined))
            return false;
        return TryNormalizeAbsoluteOrigin(joined.AbsoluteUri, out origin);
    }

    private static bool HasScheme(string value)
    {
        var separator = value.IndexOf(':');
        return separator > 0 && char.IsAsciiLetter(value[0]) &&
            value[..separator].All(character => char.IsAsciiLetterOrDigit(character) || character is '+' or '-' or '.');
    }

    private static bool TryNormalizeAbsoluteOrigin(string value, out NormalizedOrigin origin)
    {
        origin = default!;
        if (!IsSafe(value) || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo) ||
            string.IsNullOrEmpty(uri.Host) || uri.HostNameType == UriHostNameType.Unknown)
            return false;
        string host;
        string authorityHost;
        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            if (!IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address)) return false;
            host = address.ToString().ToLowerInvariant();
            authorityHost = uri.HostNameType == UriHostNameType.IPv6 ? $"[{host}]" : host;
        }
        else
        {
            try
            {
                host = new IdnMapping().GetAscii(uri.IdnHost).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return false;
            }
            if (!IsValidDnsHost(host)) return false;
            authorityHost = host;
        }
        int? port = uri.IsDefaultPort ? null : uri.Port;
        var authority = port is null ? authorityHost : $"{authorityHost}:{port.Value}";
        origin = new($"{uri.Scheme.ToLowerInvariant()}://{authority}", uri.Scheme.ToLowerInvariant(), host, port);
        return true;
    }

    private static bool IsValidDnsHost(string host) =>
        host.Length is > 0 and <= 253 && host.Split('.').All(label =>
            label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
            label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));

    private static LaravelHttpDetection Detection(NormalizedOrigin origin, PhpDocument document, Node call, string rule) =>
        new(origin.Origin, origin.Scheme, origin.Host, origin.Port,
            document.Path, document.Range(call), rule);

    private static bool IsSafe(string value) =>
        value.Length is > 0 and <= 4096 && value.All(character => !char.IsControl(character));

    private static Diagnostic Unsupported(PhpProjectModel project, PhpDocument document, Node call) =>
        new($"diagnostic:archie.php:php_laravel_http_unsupported:{Stable($"{document.Path}:{call.StartIndex}")}",
            "PHP_LARAVEL_HTTP_UNSUPPORTED", "warning",
            $"Laravel HTTP call in '{document.Path}' uses a dynamic or unsafe target and produced no external service.",
            project.Key);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private sealed record CallArgument(string? Name, Node Value);
    private sealed record FluentChain(bool IsHttpFacade, string RootName,
        IReadOnlyList<CallArgument> RootArguments, IReadOnlyList<string> Modifiers);
    private sealed record NormalizedOrigin(string Origin, string Scheme, string Host, int? Port);
}

internal sealed record LaravelHttpScanResult(
    IReadOnlyList<LaravelHttpDetection> Detections,
    IReadOnlyList<Diagnostic> Diagnostics);
