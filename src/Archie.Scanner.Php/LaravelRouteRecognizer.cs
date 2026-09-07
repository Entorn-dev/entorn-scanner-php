using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelRouteRecognizer
{
    private const string RouteFacade = "Illuminate\\Support\\Facades\\Route";
    private const string ServiceProvider = "Illuminate\\Support\\ServiceProvider";
    private static readonly IReadOnlyDictionary<string, string> Verbs =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["get"] = "GET",
            ["post"] = "POST",
            ["put"] = "PUT",
            ["patch"] = "PATCH",
            ["delete"] = "DELETE",
            ["options"] = "OPTIONS",
            ["head"] = "HEAD"
        };
    private static readonly string[] AnyMethods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];
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
            foreach (var call in document.CleanDescendants("scoped_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scope = call.GetChildForField("scope");
                var terminal = call.GetChildForField("name")?.Text;
                if (scope is null || terminal is null ||
                    !string.Equals(document.ResolveClassName(scope), RouteFacade, StringComparison.OrdinalIgnoreCase) ||
                    (!Verbs.ContainsKey(terminal) && terminal is not ("match" or "any" or "resource" or "apiResource")))
                    continue;

                if (!IsSupportedRouteSource(project, document, call) ||
                    HasUnsupportedControlFlow(call, out var groupClosures) ||
                    !TryReadGroups(document, groupClosures, out var context) ||
                    !TryReadArguments(call, out var arguments))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }

                var expression = OutermostChain(call);
                if (!TryReadRouteName(document, call, expression, out var routeName))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }
                routeName = CombineName(context.NamePrefix, routeName);

                if (terminal is "resource" or "apiResource")
                {
                    if (!TryReadResource(document, arguments, context, terminal == "apiResource", routeName,
                            expression, endpoints, project, diagnostics))
                        diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }

                if (!TryReadMethods(document, terminal, arguments, out var methods, out var uriIndex, out var actionIndex) ||
                    arguments.Count <= actionIndex || document.Literal(arguments[uriIndex]) is not { } uri ||
                    !TryNormalizeTemplate(context.Prefix, uri, out var template))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }

                var action = ReadAction(document, arguments[actionIndex], context.Controller, project);
                foreach (var method in methods)
                    endpoints.Add(new(method, template, context.Domain, routeName, action.Controller, action.Method,
                        document.Path, document.Range(expression), action.Rule, action.Confidence, action.Resolution));
                if (action.Resolution != Resolution.Resolved)
                    diagnostics.Add(Unresolved(project, document, call, methods[0], template, action));
            }
        }

        if (project.Packages.Any(item =>
                item.Name.Equals("spatie/laravel-route-attributes", StringComparison.OrdinalIgnoreCase)))
        {
            var attributeScan = LaravelRouteAttributeRecognizer.Scan(project, cancellationToken);
            endpoints.AddRange(attributeScan.Endpoints);
            diagnostics.AddRange(attributeScan.Diagnostics);
        }

        return new(
            endpoints.OrderBy(item => item.Method, StringComparer.Ordinal)
                .ThenBy(item => item.Domain, StringComparer.Ordinal)
                .ThenBy(item => item.Template, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.Range.StartLine).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static bool TryReadMethods(PhpDocument document, string terminal, IReadOnlyList<Node> arguments,
        out IReadOnlyList<string> methods, out int uriIndex, out int actionIndex)
    {
        uriIndex = 0;
        actionIndex = 1;
        if (Verbs.TryGetValue(terminal, out var verb) && arguments.Count == 2)
        {
            methods = [verb];
            return true;
        }
        if (terminal == "any" && arguments.Count == 2)
        {
            methods = AnyMethods;
            return true;
        }
        if (terminal == "match" && arguments.Count == 3 &&
            TryReadLiteralArray(document, arguments[0], out var values) && values.Count is > 0 and <= 16)
        {
            var normalized = values.Select(item => item.ToUpperInvariant()).Distinct(StringComparer.Ordinal).ToArray();
            if (normalized.All(item => Verbs.Values.Contains(item, StringComparer.Ordinal)))
            {
                methods = normalized;
                uriIndex = 1;
                actionIndex = 2;
                return true;
            }
        }
        methods = [];
        return false;
    }

    private static bool TryReadResource(PhpDocument document, IReadOnlyList<Node> arguments, RouteContext context,
        bool apiOnly, string? routeName, Node expression, ICollection<LaravelEndpointDetection> endpoints,
        PhpProjectModel project, ICollection<Diagnostic> diagnostics)
    {
        if (arguments.Count != 2 || document.Literal(arguments[0]) is not { } uri ||
            !TryNormalizeTemplate(context.Prefix, uri, out var template) ||
            !TryReadClassConstant(document, arguments[1], out var controller))
            return false;

        var parameter = ResourceParameter(template);
        RouteAction? unresolved = null;
        foreach (var route in ResourceRoutes.Where(item => !apiOnly || item.Action is not ("create" or "edit")))
        {
            var suffix = route.Suffix.Replace("{parameter}", $"{{{parameter}}}", StringComparison.Ordinal);
            var action = ResolveAction(controller, route.Action, project, "laravel:literal-resource-route");
            endpoints.Add(new(route.Method, template + suffix, context.Domain, routeName, action.Controller,
                action.Method, document.Path, document.Range(expression), action.Rule,
                action.Confidence, action.Resolution));
            if (action.Resolution != Resolution.Resolved) unresolved ??= action;
        }
        if (unresolved is not null)
            diagnostics.Add(Unresolved(project, document, expression, "RESOURCE", template, unresolved));
        return true;
    }

    private static RouteAction ReadAction(PhpDocument document, Node expression, string? groupController,
        PhpProjectModel project)
    {
        if (expression.Type is "anonymous_function" or "arrow_function")
            return new(null, null, "laravel:literal-closure-route", Confidence.Inferred, Resolution.Resolved);
        if (TryReadControllerArray(document, expression, out var controller, out var method))
            return ResolveAction(controller, method, project, "laravel:literal-controller-route");
        if (TryReadClassConstant(document, expression, out controller))
            return ResolveAction(controller, "__invoke", project, "laravel:literal-invokable-route");
        if (document.Literal(expression) is { } literal)
        {
            var separator = literal.LastIndexOf('@');
            if (separator > 0 && separator < literal.Length - 1 && literal[..separator].Contains('\\'))
                return ResolveAction(document.ResolveClassName(literal[..separator]), literal[(separator + 1)..],
                    project, "laravel:literal-string-controller-route");
            if (groupController is not null && IsIdentifier(literal))
                return ResolveAction(groupController, literal, project, "laravel:literal-group-controller-route");
        }
        return new(groupController, null, "laravel:literal-route-unresolved-action",
            Confidence.Confirmed, Resolution.Unresolved);
    }

    private static RouteAction ResolveAction(string? controller, string method, PhpProjectModel project, string rule)
    {
        var resolved = controller is not null && project.Classes.TryGetValue(controller, out var declaration) &&
            declaration.Kind == PhpTypeKind.Class && declaration.Methods.Contains(method);
        return new(controller, method, rule, Confidence.Confirmed,
            resolved ? Resolution.Resolved : Resolution.Unresolved);
    }

    private static bool TryReadGroups(PhpDocument document, IReadOnlyList<Node> closures, out RouteContext context)
    {
        context = new(null, null, null, null);
        foreach (var closure in closures.Reverse())
        {
            if (!TryFindContainingCall(closure, out var call) || !TryReadGroupChain(document, call, out var group))
                return false;
            context = new(
                CombinePrefix(context.Prefix, group.Prefix),
                group.Domain ?? context.Domain,
                CombineName(context.NamePrefix, group.NamePrefix),
                group.Controller ?? context.Controller);
        }
        return true;
    }

    private static bool TryReadGroupChain(PhpDocument document, Node call, out RouteContext context)
    {
        context = new(null, null, null, null);
        if (call.GetChildForField("name")?.Text != "group") return false;
        if (call.Type == "scoped_call_expression")
        {
            if (call.GetChildForField("scope") is not { } scope ||
                !string.Equals(document.ResolveClassName(scope), RouteFacade, StringComparison.OrdinalIgnoreCase) ||
                !TryReadArguments(call, out var groupArguments) || groupArguments.Count is < 1 or > 2)
                return false;
            return groupArguments.Count == 1 ||
                groupArguments[0].Type == "array_creation_expression" &&
                !groupArguments[0].NamedChildren.Any(item => item.Type == "array_element_initializer");
        }
        if (call.Type != "member_call_expression") return false;
        var chain = new List<(string Name, IReadOnlyList<Node> Arguments)>();
        if (!ReadChain(document, call.GetChildForField("object"), chain)) return false;
        foreach (var item in chain)
        {
            if (item.Name is "middleware" or "withoutMiddleware") continue;
            if (item.Arguments.Count != 1) return false;
            if (item.Name == "prefix" && document.Literal(item.Arguments[0]) is { } prefix)
                context = context with { Prefix = CombinePrefix(context.Prefix, prefix) };
            else if (item.Name == "domain" && document.Literal(item.Arguments[0]) is { } domain && IsSafe(domain))
                context = context with { Domain = domain };
            else if (item.Name == "name" && document.Literal(item.Arguments[0]) is { } name && IsSafe(name))
                context = context with { NamePrefix = CombineName(context.NamePrefix, name) };
            else if (item.Name == "controller" && TryReadClassConstant(document, item.Arguments[0], out var controller))
                context = context with { Controller = controller };
            else return false;
        }
        return true;
    }

    private static bool IsSupportedRouteSource(PhpProjectModel project, PhpDocument document, Node call)
    {
        if (document.Path.StartsWith("routes/", StringComparison.OrdinalIgnoreCase) ||
            document.Path.Contains("/routes/", StringComparison.OrdinalIgnoreCase)) return true;
        if (!Ancestors(call).Any(item => item.Type == "method_declaration")) return false;
        var range = document.Range(call);
        return project.Classes.Values.Any(declaration =>
            string.Equals(declaration.Path, document.Path, StringComparison.Ordinal) &&
            declaration.BaseTypes.Contains(ServiceProvider, StringComparer.OrdinalIgnoreCase) &&
            Contains(declaration.Range, range));
    }

    private static IEnumerable<Node> Ancestors(Node node)
    {
        for (var parent = node.Parent; parent is not null; parent = parent.Parent) yield return parent;
    }

    private static bool Contains(SourceRange container, SourceRange value) =>
        (value.StartLine > container.StartLine ||
         value.StartLine == container.StartLine && value.StartColumn >= container.StartColumn) &&
        (value.EndLine < container.EndLine ||
         value.EndLine == container.EndLine && value.EndColumn <= container.EndColumn);

    private static bool ReadChain(PhpDocument document, Node? expression,
        ICollection<(string Name, IReadOnlyList<Node> Arguments)> chain)
    {
        if (expression is null) return false;
        if (expression.Type == "member_call_expression")
        {
            if (!ReadChain(document, expression.GetChildForField("object"), chain) ||
                expression.GetChildForField("name")?.Text is not { } name ||
                !TryReadArguments(expression, out var arguments)) return false;
            chain.Add((name, arguments));
            return true;
        }
        if (expression.Type != "scoped_call_expression" ||
            expression.GetChildForField("scope") is not { } scope ||
            !string.Equals(document.ResolveClassName(scope), RouteFacade, StringComparison.OrdinalIgnoreCase) ||
            expression.GetChildForField("name")?.Text is not { } rootName ||
            !TryReadArguments(expression, out var rootArguments)) return false;
        chain.Add((rootName, rootArguments));
        return true;
    }

    private static bool HasUnsupportedControlFlow(Node call, out IReadOnlyList<Node> groupClosures)
    {
        var closures = new List<Node>();
        for (var parent = call.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent.Type is "if_statement" or "switch_statement" or "while_statement" or "do_statement" or
                "for_statement" or "foreach_statement" or "conditional_expression" or "match_expression")
            {
                groupClosures = [];
                return true;
            }
            if (parent.Type is "anonymous_function" or "arrow_function") closures.Add(parent);
            if (parent.Type is "function_definition")
            {
                groupClosures = [];
                return true;
            }
        }
        groupClosures = closures;
        return false;
    }

    private static bool TryFindContainingCall(Node closure, out Node call)
    {
        for (var parent = closure.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent.Type is "member_call_expression" or "scoped_call_expression")
            {
                call = parent;
                return true;
            }
            if (parent.Type is not ("argument" or "arguments")) break;
        }
        call = null!;
        return false;
    }

    private static Node OutermostChain(Node call)
    {
        var expression = call;
        while (expression.Parent is { Type: "member_call_expression" } parent &&
            SameNode(parent.GetChildForField("object"), expression))
            expression = parent;
        return expression;
    }

    private static bool TryReadRouteName(PhpDocument document, Node routeCall, Node outermost, out string? name)
    {
        name = null;
        var expression = routeCall;
        while (!SameNode(expression, outermost))
        {
            var parent = expression.Parent;
            if (parent is null || parent.Type != "member_call_expression" ||
                !SameNode(parent.GetChildForField("object"), expression) ||
                parent.GetChildForField("name")?.Text is not { } modifier ||
                !TryReadArguments(parent, out var arguments)) return false;
            if (modifier == "name" && arguments.Count == 1 && document.Literal(arguments[0]) is { } value && IsSafe(value))
                name = value;
            else if (modifier is not ("middleware" or "withoutMiddleware")) return false;
            expression = parent;
        }
        return true;
    }

    private static bool TryReadControllerArray(PhpDocument document, Node expression,
        out string? controller, out string method)
    {
        controller = null;
        method = string.Empty;
        if (expression.Type != "array_creation_expression") return false;
        var elements = expression.NamedChildren.Where(item => item.Type == "array_element_initializer").ToArray();
        if (elements.Length != 2) return false;
        var first = ElementValue(elements[0]);
        var second = ElementValue(elements[1]);
        return first is not null && second is not null && TryReadClassConstant(document, first, out controller) &&
            document.Literal(second) is { } value && IsIdentifier(value) && (method = value).Length > 0;
    }

    private static bool TryReadClassConstant(PhpDocument document, Node expression, out string? className)
    {
        className = null;
        if (expression.Type != "class_constant_access_expression" || expression.NamedChildren.Count != 2) return false;
        var classNode = expression.GetChildForField("class") ?? expression.NamedChildren[0];
        var constant = (expression.GetChildForField("constant") ?? expression.NamedChildren[1]).Text;
        if (!string.Equals(constant, "class", StringComparison.OrdinalIgnoreCase)) return false;
        className = document.ResolveClassName(classNode);
        return className is not null;
    }

    private static bool TryReadArguments(Node call, out IReadOnlyList<Node> arguments)
    {
        var container = call.GetChildForField("arguments");
        if (container is null)
        {
            arguments = [];
            return false;
        }
        var result = new List<Node>();
        foreach (var argument in container.NamedChildren)
        {
            if (argument.Type != "argument" || argument.NamedChildren.Count != 1)
            {
                arguments = [];
                return false;
            }
            result.Add(argument.NamedChildren[0]);
        }
        arguments = result;
        return true;
    }

    private static bool TryReadLiteralArray(PhpDocument document, Node expression, out IReadOnlyList<string> values)
    {
        values = [];
        if (expression.Type != "array_creation_expression") return false;
        var result = new List<string>();
        foreach (var element in expression.NamedChildren.Where(item => item.Type == "array_element_initializer"))
        {
            var value = ElementValue(element);
            if (value is null || document.Literal(value) is not { } literal || !IsIdentifier(literal)) return false;
            result.Add(literal);
        }
        values = result;
        return true;
    }

    private static Node? ElementValue(Node element) =>
        element.GetChildForField("value") ?? element.NamedChildren.LastOrDefault();

    private static bool TryNormalizeTemplate(string? prefix, string uri, out string template)
    {
        template = string.Empty;
        if (!IsSafe(uri) || !IsSafe(prefix ?? string.Empty)) return false;
        template = CombinePrefix(prefix, uri) ?? "/";
        if (!template.StartsWith('/')) template = "/" + template;
        return template.Length <= 2048;
    }

    private static string? CombinePrefix(string? left, string? right)
    {
        var combined = $"{left?.Trim('/')}/{right?.Trim('/')}".Trim('/');
        return combined.Length == 0 ? "/" : $"/{combined}";
    }

    private static string? CombineName(string? left, string? right) =>
        left is null ? right : right is null ? left : left + right;

    private static string ResourceParameter(string template)
    {
        var segment = template.Trim('/').Split('/').LastOrDefault() ?? "resource";
        segment = new string(segment.Where(character => char.IsLetterOrDigit(character) || character == '_').ToArray());
        if (segment.EndsWith("ies", StringComparison.Ordinal) && segment.Length > 3)
            segment = segment[..^3] + "y";
        else if (segment.EndsWith('s') && segment.Length > 1) segment = segment[..^1];
        return IsIdentifier(segment) ? segment : "resource";
    }

    private static bool IsSafe(string value) =>
        value.Length <= 2048 && value.All(character => !char.IsControl(character));

    private static bool IsIdentifier(string value) =>
        value.Length > 0 && (char.IsLetter(value[0]) || value[0] == '_') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_');

    private static bool SameNode(Node? left, Node right) =>
        left is not null && left.StartIndex == right.StartIndex && left.EndIndex == right.EndIndex && left.Type == right.Type;

    private static Diagnostic Unsupported(PhpProjectModel project, PhpDocument document, Node call) =>
        Diagnostic("PHP_LARAVEL_ROUTE_UNSUPPORTED",
            $"Laravel route registration in '{document.Path}' uses a dynamic or unsupported form and produced no endpoint.",
            project.Key, $"{document.Path}:{call.StartIndex}");

    private static Diagnostic Unresolved(PhpProjectModel project, PhpDocument document, Node call,
        string method, string template, RouteAction action) =>
        Diagnostic("PHP_LARAVEL_CONTROLLER_UNRESOLVED",
            $"Laravel route {method} {template} references an application controller or action that could not be resolved.",
            project.Key, $"{document.Path}:{call.StartIndex}:{action.Controller}:{action.Method}");

    private static Diagnostic Diagnostic(string code, string message, string? subject, string key) =>
        new($"diagnostic:archie.php:{code.ToLowerInvariant()}:{Stable(key)}", code, "warning", message, subject);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private sealed record RouteContext(string? Prefix, string? Domain, string? NamePrefix, string? Controller);
    private sealed record RouteAction(string? Controller, string? Method, string Rule,
        Confidence Confidence, Resolution Resolution);
}
