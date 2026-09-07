using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelRouteAttributeRecognizer
{
    private const string AttributeNamespace = "Spatie\\RouteAttributes\\Attributes\\";
    private static readonly IReadOnlyDictionary<string, string> VerbAttributes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [$"{AttributeNamespace}Get"] = "GET",
            [$"{AttributeNamespace}Post"] = "POST",
            [$"{AttributeNamespace}Put"] = "PUT",
            [$"{AttributeNamespace}Patch"] = "PATCH",
            [$"{AttributeNamespace}Delete"] = "DELETE",
            [$"{AttributeNamespace}Options"] = "OPTIONS"
        };
    private static readonly string[] HttpMethods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];
    private static readonly (string Method, string Suffix, string Action)[] ResourceRoutes =
    [
        ("GET", "", "index"), ("GET", "/create", "create"), ("POST", "", "store"),
        ("GET", "/{parameter}", "show"), ("GET", "/{parameter}/edit", "edit"),
        ("PUT", "/{parameter}", "update"), ("PATCH", "/{parameter}", "update"),
        ("DELETE", "/{parameter}", "destroy")
    ];

    public static LaravelScanResult Scan(PhpProjectModel project, CancellationToken cancellationToken)
    {
        var endpoints = new List<LaravelEndpointDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var classNode in document.CleanDescendants("class_declaration"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var declaration = project.Classes.Values.FirstOrDefault(item =>
                    string.Equals(item.Path, document.Path, StringComparison.Ordinal) &&
                    item.Range == document.Range(classNode));
                if (declaration is null) continue;

                var classAttributes = DirectAttributes(classNode).ToArray();
                if (!TryReadClassContext(document, classAttributes, out var context, out var contextFailure))
                {
                    diagnostics.Add(Unsupported(project, document, contextFailure!));
                    continue;
                }
                ReadResourceAttributes(document, project, declaration, classAttributes, context,
                    endpoints, diagnostics);

                foreach (var methodNode in classNode.NamedChildren
                             .Where(item => item.Type == "declaration_list")
                             .SelectMany(item => item.NamedChildren)
                             .Where(item => item.Type == "method_declaration"))
                {
                    var method = methodNode.GetChildForField("name")?.Text;
                    if (method is null) continue;
                    foreach (var attribute in DirectAttributes(methodNode))
                    {
                        var attributeName = AttributeName(document, attribute);
                        if (attributeName is null ||
                            !VerbAttributes.ContainsKey(attributeName) &&
                            !attributeName.Equals($"{AttributeNamespace}Route", StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (!TryReadMethodRoute(document, attribute, attributeName, out var methods,
                                out var uri, out var routeName) || !TryNormalizeTemplate(context.Prefix, uri, out var template))
                        {
                            diagnostics.Add(Unsupported(project, document, attribute));
                            continue;
                        }
                        foreach (var httpMethod in methods)
                            endpoints.Add(new(httpMethod, template, context.Domain, routeName,
                                declaration.FullyQualifiedName, method, document.Path, document.Range(attribute),
                                "laravel:spatie-route-attribute", Confidence.Inferred, Resolution.Resolved));
                    }
                }
            }
        }
        return new(endpoints, diagnostics.DistinctBy(item => item.Id).ToArray());
    }

    private static bool TryReadClassContext(PhpDocument document, IReadOnlyList<Node> attributes,
        out AttributeContext context, out Node? failure)
    {
        context = new(null, null);
        failure = null;
        foreach (var attribute in attributes)
        {
            var name = AttributeName(document, attribute);
            if (name is null) continue;
            var isPrefix = name.Equals($"{AttributeNamespace}Prefix", StringComparison.OrdinalIgnoreCase);
            var isDomain = name.Equals($"{AttributeNamespace}Domain", StringComparison.OrdinalIgnoreCase);
            if (!isPrefix && !isDomain) continue;
            if (!TryReadArguments(attribute, out var arguments) ||
                FindArgument(arguments, isPrefix ? "prefix" : "domain", 0) is not { } expression ||
                document.Literal(expression) is not { } literal || !IsSafe(literal))
            {
                failure = attribute;
                return false;
            }
            context = isPrefix ? context with { Prefix = literal } : context with { Domain = literal };
        }
        return true;
    }

    private static void ReadResourceAttributes(PhpDocument document, PhpProjectModel project,
        PhpClassDeclaration declaration, IReadOnlyList<Node> attributes, AttributeContext context,
        ICollection<LaravelEndpointDetection> endpoints, ICollection<Diagnostic> diagnostics)
    {
        foreach (var attribute in attributes)
        {
            var name = AttributeName(document, attribute);
            var isResource = name?.Equals($"{AttributeNamespace}Resource", StringComparison.OrdinalIgnoreCase) == true;
            var isApiResource = name?.Equals($"{AttributeNamespace}ApiResource", StringComparison.OrdinalIgnoreCase) == true;
            if (!isResource && !isApiResource) continue;
            if (!TryReadArguments(attribute, out var arguments) ||
                FindArgument(arguments, "resource", 0) is not { } resourceExpression ||
                document.Literal(resourceExpression) is not { } resource ||
                !TryNormalizeTemplate(context.Prefix, resource, out var template) ||
                !TryReadOptionalMethodFilter(document, arguments, "only", isApiResource ? 2 : 3, out var only) ||
                !TryReadOptionalMethodFilter(document, arguments, "except", isApiResource ? 1 : 2, out var except) ||
                HasUnsupportedResourceIdentityArguments(arguments, isApiResource) ||
                !TryReadApiResource(arguments, isApiResource, out var apiResource))
            {
                diagnostics.Add(Unsupported(project, document, attribute));
                continue;
            }
            var parameter = ResourceParameter(template);
            foreach (var route in ResourceRoutes.Where(item => (!apiResource || item.Action is not ("create" or "edit")) &&
                         (only.Count == 0 || only.Contains(item.Action)) && !except.Contains(item.Action)))
            {
                var suffix = route.Suffix.Replace("{parameter}", $"{{{parameter}}}", StringComparison.Ordinal);
                endpoints.Add(new(route.Method, template + suffix, context.Domain, null,
                    declaration.FullyQualifiedName, route.Action, document.Path, document.Range(attribute),
                    "laravel:spatie-resource-attribute", Confidence.Inferred,
                    declaration.Methods.Contains(route.Action) ? Resolution.Resolved : Resolution.Unresolved));
            }
        }
    }

    private static bool TryReadMethodRoute(PhpDocument document, Node attribute, string attributeName,
        out IReadOnlyList<string> methods, out string uri, out string? routeName)
    {
        methods = [];
        uri = string.Empty;
        routeName = null;
        if (!TryReadArguments(attribute, out var arguments)) return false;
        var generic = attributeName.Equals($"{AttributeNamespace}Route", StringComparison.OrdinalIgnoreCase);
        var uriPosition = generic ? 1 : 0;
        if (FindArgument(arguments, "uri", uriPosition) is not { } uriExpression ||
            document.Literal(uriExpression) is not { } literalUri || !IsSafe(literalUri)) return false;
        uri = literalUri;
        if (FindArgument(arguments, "name", uriPosition + 1) is { } nameExpression)
        {
            routeName = document.Literal(nameExpression);
            if (routeName is null || !IsSafe(routeName)) return false;
        }
        if (!generic)
        {
            methods = [VerbAttributes[attributeName]];
            return true;
        }
        if (FindArgument(arguments, "methods", 0) is not { } methodsExpression ||
            !TryReadStringOrArray(document, methodsExpression, out var values)) return false;
        var normalized = values.Select(item => item.ToUpperInvariant()).Distinct(StringComparer.Ordinal).ToArray();
        if (normalized.Length == 0 || normalized.Any(item => !HttpMethods.Contains(item, StringComparer.Ordinal)))
            return false;
        methods = normalized;
        return true;
    }

    private static bool TryReadApiResource(IReadOnlyList<AttributeArgument> arguments,
        bool apiResourceAttribute, out bool apiResource)
    {
        apiResource = apiResourceAttribute;
        if (apiResourceAttribute) return true;
        var expression = FindArgument(arguments, "apiResource", 1);
        if (expression is null) return true;
        if (expression.Text.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            apiResource = true;
            return true;
        }
        return expression.Text.Equals("false", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasUnsupportedResourceIdentityArguments(
        IReadOnlyList<AttributeArgument> arguments,
        bool apiResourceAttribute) =>
        arguments.Any(item => item.Name is "names" or "parameters" or "shallow") ||
        arguments.Count > (apiResourceAttribute ? 3 : 4);

    private static IEnumerable<Node> DirectAttributes(Node declaration) =>
        declaration.NamedChildren.Where(item => item.Type == "attribute_list")
            .SelectMany(item => item.NamedChildren)
            .SelectMany(item => item.NamedChildren)
            .Where(item => item.Type == "attribute");

    private static string? AttributeName(PhpDocument document, Node attribute) =>
        attribute.NamedChildren.FirstOrDefault(item => item.Type is "name" or "qualified_name") is { } name
            ? document.ResolveClassName(name) : null;

    private static bool TryReadArguments(Node attribute, out IReadOnlyList<AttributeArgument> arguments)
    {
        var container = attribute.NamedChildren.FirstOrDefault(item => item.Type == "arguments");
        if (container is null)
        {
            arguments = [];
            return true;
        }
        var result = new List<AttributeArgument>();
        foreach (var argument in container.NamedChildren)
        {
            if (argument.Type != "argument" || argument.NamedChildren.Count is < 1 or > 2)
            {
                arguments = [];
                return false;
            }
            var named = argument.NamedChildren.Count == 2 ? argument.NamedChildren[0].Text : null;
            result.Add(new(named, argument.NamedChildren[^1]));
        }
        arguments = result;
        return true;
    }

    private static Node? FindArgument(IReadOnlyList<AttributeArgument> arguments, string name, int position) =>
        arguments.FirstOrDefault(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))?.Value ??
        (position < arguments.Count && arguments[position].Name is null ? arguments[position].Value : null);

    private static bool TryReadOptionalMethodFilter(PhpDocument document, IReadOnlyList<AttributeArgument> arguments,
        string name, int position, out IReadOnlySet<string> methods)
    {
        methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var expression = FindArgument(arguments, name, position);
        if (expression is null) return true;
        if (!TryReadStringOrArray(document, expression, out var values) || values.Any(item => !IsIdentifier(item)))
            return false;
        methods = values.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return true;
    }

    private static bool TryReadStringOrArray(PhpDocument document, Node expression, out IReadOnlyList<string> values)
    {
        if (document.Literal(expression) is { } literal)
        {
            values = [literal];
            return true;
        }
        if (expression.Type != "array_creation_expression")
        {
            values = [];
            return false;
        }
        var result = new List<string>();
        foreach (var element in expression.NamedChildren.Where(item => item.Type == "array_element_initializer"))
        {
            var value = element.GetChildForField("value") ?? element.NamedChildren.LastOrDefault();
            if (value is null || document.Literal(value) is not { } item) { values = []; return false; }
            result.Add(item);
        }
        values = result;
        return true;
    }

    private static bool TryNormalizeTemplate(string? prefix, string uri, out string template)
    {
        var combined = $"{prefix?.Trim('/')}/{uri.Trim('/')}".Trim('/');
        template = combined.Length == 0 ? "/" : $"/{combined}";
        return IsSafe(uri) && IsSafe(prefix ?? string.Empty) && template.Length <= 2048;
    }

    private static string ResourceParameter(string template)
    {
        var segment = new string((template.Trim('/').Split('/').LastOrDefault() ?? "resource")
            .Where(character => char.IsLetterOrDigit(character) || character == '_').ToArray());
        if (segment.EndsWith("ies", StringComparison.Ordinal) && segment.Length > 3) segment = segment[..^3] + "y";
        else if (segment.EndsWith('s') && segment.Length > 1) segment = segment[..^1];
        return IsIdentifier(segment) ? segment : "resource";
    }

    private static bool IsSafe(string value) =>
        value.Length <= 2048 && value.All(character => !char.IsControl(character));

    private static bool IsIdentifier(string value) =>
        value.Length > 0 && (char.IsLetter(value[0]) || value[0] == '_') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_');

    private static Diagnostic Unsupported(PhpProjectModel project, PhpDocument document, Node node) =>
        new($"diagnostic:archie.php:php_laravel_route_attribute_unsupported:{Stable($"{document.Path}:{node.StartIndex}")}",
            "PHP_LARAVEL_ROUTE_ATTRIBUTE_UNSUPPORTED", "warning",
            $"Laravel route attribute in '{document.Path}' uses a dynamic or unsupported form and produced no endpoint.",
            project.Key);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private sealed record AttributeContext(string? Prefix, string? Domain);
    private sealed record AttributeArgument(string? Name, Node Value);
}
