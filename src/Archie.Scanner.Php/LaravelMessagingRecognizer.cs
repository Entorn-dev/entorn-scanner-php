using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelMessagingRecognizer
{
    private const string ShouldQueue = "Illuminate\\Contracts\\Queue\\ShouldQueue";
    private const string BusFacade = "Illuminate\\Support\\Facades\\Bus";
    private const string QueueFacade = "Illuminate\\Support\\Facades\\Queue";
    private const string EventFacade = "Illuminate\\Support\\Facades\\Event";
    private const string EventDispatchable = "Illuminate\\Foundation\\Events\\Dispatchable";
    private const string EventServiceProvider = "Illuminate\\Foundation\\Support\\Providers\\EventServiceProvider";

    public static LaravelMessagingScanResult ScanJobs(
        PhpProjectModel project,
        CancellationToken cancellationToken)
    {
        var dispatches = new List<LaravelJobDispatchDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var call in document.CleanDescendants("scoped_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scope = call.GetChildForField("scope");
                var method = call.GetChildForField("name")?.Text;
                if (scope is null || method is null) continue;
                var receiver = document.ResolveClassName(scope);
                if (receiver is null) continue;

                if ((method.Equals("dispatch", StringComparison.OrdinalIgnoreCase) ||
                     method.Equals("dispatchSync", StringComparison.OrdinalIgnoreCase)) &&
                    project.Classes.TryGetValue(receiver, out var staticJob) &&
                    staticJob.Kind == PhpTypeKind.Class)
                {
                    if (PhpTypeRelations.IsAssignableTo(project, receiver, ShouldQueue))
                        dispatches.Add(Detection(staticJob, document, call, "laravel:queued-job-static-dispatch"));
                    continue;
                }

                var isBus = receiver.Equals(BusFacade, StringComparison.OrdinalIgnoreCase) &&
                            method.Equals("dispatch", StringComparison.OrdinalIgnoreCase);
                var isQueue = receiver.Equals(QueueFacade, StringComparison.OrdinalIgnoreCase) &&
                              method.Equals("push", StringComparison.OrdinalIgnoreCase);
                if (!isBus && !isQueue) continue;
                if (!TryReadArguments(call, out var arguments) ||
                    FindArgument(arguments, isBus ? "command" : "job", 0) is not { } expression ||
                    !TryReadQueuedJob(project, document, expression, out var job))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }
                dispatches.Add(Detection(job, document, call,
                    isBus ? "laravel:queued-job-bus-dispatch" : "laravel:queued-job-queue-push"));
            }

            foreach (var call in document.CleanDescendants("function_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var function = call.GetChildForField("function");
                if (function is null || !IsLaravelDispatchHelper(document, function)) continue;
                if (!TryReadArguments(call, out var arguments) ||
                    FindArgument(arguments, "job", 0) is not { } expression ||
                    !TryReadQueuedJob(project, document, expression, out var job))
                {
                    diagnostics.Add(Unsupported(project, document, call));
                    continue;
                }
                dispatches.Add(Detection(job, document, call, "laravel:queued-job-helper-dispatch"));
            }
        }

        return new(
            dispatches.OrderBy(item => item.JobType, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal)
                .ThenBy(item => item.Range.StartLine).ThenBy(item => item.Range.StartColumn).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    public static LaravelEventScanResult ScanEvents(
        PhpProjectModel project,
        CancellationToken cancellationToken)
    {
        var publications = new List<LaravelEventPublicationDetection>();
        var subscriptions = new List<LaravelEventSubscriptionDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var call in document.CleanDescendants("scoped_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scope = call.GetChildForField("scope");
                var method = call.GetChildForField("name")?.Text;
                if (scope is null || method is null) continue;
                var receiver = document.ResolveClassName(scope);
                if (receiver is null) continue;

                if (receiver.Equals(EventFacade, StringComparison.OrdinalIgnoreCase) &&
                    method.Equals("dispatch", StringComparison.OrdinalIgnoreCase))
                {
                    if (!TryReadArguments(call, out var arguments) ||
                        FindArgument(arguments, "event", 0) is not { } expression ||
                        !TryReadEventChannel(project, document, expression, allowNew: true, out var channel))
                        diagnostics.Add(UnsupportedEvent(project, document, call));
                    else
                        publications.Add(Publication(channel, document, call, "laravel:event-facade-dispatch"));
                    continue;
                }

                if (receiver.Equals(EventFacade, StringComparison.OrdinalIgnoreCase) &&
                    method.Equals("listen", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasUnsupportedRegistrationContext(call) || !TryReadArguments(call, out var arguments) ||
                        FindArgument(arguments, "events", 0) is not { } eventExpression ||
                        FindArgument(arguments, "listener", 1) is not { } listenerExpression ||
                        !TryReadEventChannel(project, document, eventExpression, allowNew: false, out var channel) ||
                        !TryReadListener(project, document, listenerExpression, out var listener, out var listenerMethod))
                        diagnostics.Add(UnsupportedListener(project, document, call));
                    else
                        subscriptions.Add(Subscription(channel, listener, listenerMethod, project,
                            document, call, "laravel:event-facade-listen"));
                    continue;
                }

                if (method.Equals("dispatch", StringComparison.OrdinalIgnoreCase) &&
                    project.Classes.TryGetValue(receiver, out var eventDeclaration) &&
                    eventDeclaration.Kind == PhpTypeKind.Class &&
                    PhpTypeRelations.IsAssignableTo(project, receiver, EventDispatchable))
                    publications.Add(Publication(EventChannel(eventDeclaration), document, call,
                        "laravel:event-static-dispatch"));
            }

            foreach (var call in document.CleanDescendants("function_call_expression"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var function = call.GetChildForField("function");
                if (function is null || !IsLaravelGlobalHelper(document, function, "event")) continue;
                if (!TryReadArguments(call, out var arguments) ||
                    FindArgument(arguments, "event", 0) is not { } expression ||
                    !TryReadEventChannel(project, document, expression, allowNew: true, out var channel))
                    diagnostics.Add(UnsupportedEvent(project, document, call));
                else
                    publications.Add(Publication(channel, document, call, "laravel:event-helper"));
            }

            ReadProviderListeners(project, document, subscriptions, diagnostics);
        }

        return new(
            publications.OrderBy(item => item.ChannelKey, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal).ThenBy(item => item.Range.StartLine).ToArray(),
            subscriptions.OrderBy(item => item.ChannelKey, StringComparer.Ordinal)
                .ThenBy(item => item.ListenerType, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal).ThenBy(item => item.Range.StartLine).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static void ReadProviderListeners(
        PhpProjectModel project,
        PhpDocument document,
        ICollection<LaravelEventSubscriptionDetection> subscriptions,
        ICollection<Diagnostic> diagnostics)
    {
        foreach (var classNode in document.CleanDescendants("class_declaration"))
        {
            var declaration = project.Index.TypesByPath.GetValueOrDefault(document.Path)?.FirstOrDefault(item =>
                item.Kind == PhpTypeKind.Class && item.Range == document.Range(classNode));
            if (declaration is null ||
                !PhpTypeRelations.IsAssignableTo(project, declaration.FullyQualifiedName, EventServiceProvider))
                continue;
            foreach (var property in classNode.NamedChildren.Where(item => item.Type == "declaration_list")
                         .SelectMany(item => item.NamedChildren).Where(item => item.Type == "property_declaration"))
            {
                var element = property.NamedChildren.FirstOrDefault(item => item.Type == "property_element");
                if (element?.NamedChildren.Count != 2 || element.NamedChildren[0].Text != "$listen" ||
                    element.NamedChildren[1].Type != "array_creation_expression") continue;
                foreach (var registration in element.NamedChildren[1].NamedChildren
                             .Where(item => item.Type == "array_element_initializer"))
                {
                    if (registration.NamedChildren.Count != 2 ||
                        !TryReadEventChannel(project, document, registration.NamedChildren[0], allowNew: false,
                            out var channel) || registration.NamedChildren[1].Type != "array_creation_expression")
                    {
                        diagnostics.Add(UnsupportedListener(project, document, registration));
                        continue;
                    }
                    var valid = true;
                    foreach (var listenerElement in registration.NamedChildren[1].NamedChildren
                                 .Where(item => item.Type == "array_element_initializer"))
                    {
                        var expression = listenerElement.NamedChildren.LastOrDefault();
                        if (expression is null ||
                            !TryReadListener(project, document, expression, out var listener, out var listenerMethod))
                        {
                            valid = false;
                            continue;
                        }
                        subscriptions.Add(Subscription(channel, listener, listenerMethod, project,
                            document, listenerElement, "laravel:event-provider-listen-map"));
                    }
                    if (!valid) diagnostics.Add(UnsupportedListener(project, document, registration));
                }
            }
        }
    }

    private static bool TryReadEventChannel(PhpProjectModel project, PhpDocument document, Node expression,
        bool allowNew, out EventChannelReference channel)
    {
        channel = default!;
        if (allowNew && expression.Type == "object_creation_expression")
        {
            var classNode = expression.NamedChildren.FirstOrDefault(item => item.Type is "name" or "qualified_name");
            var typeName = classNode is null ? null : document.ResolveClassName(classNode);
            if (typeName is null || !project.Classes.TryGetValue(typeName, out var declaration) ||
                declaration.Kind != PhpTypeKind.Class) return false;
            channel = EventChannel(declaration);
            return true;
        }
        if (TryReadClassConstant(document, expression, out var className) && className is not null &&
            project.Classes.TryGetValue(className, out var eventDeclaration) &&
            eventDeclaration.Kind == PhpTypeKind.Class)
        {
            channel = EventChannel(eventDeclaration);
            return true;
        }
        if (document.Literal(expression) is { } eventName && IsEventName(eventName))
        {
            channel = new($"name:{eventName}", eventName, null);
            return true;
        }
        return false;
    }

    private static bool TryReadListener(PhpProjectModel project, PhpDocument document, Node expression,
        out PhpClassDeclaration listener, out string method)
    {
        listener = null!;
        method = string.Empty;
        string? className;
        if (TryReadClassConstant(document, expression, out className)) method = "handle";
        else if (expression.Type == "array_creation_expression")
        {
            var elements = expression.NamedChildren.Where(item => item.Type == "array_element_initializer").ToArray();
            var classExpression = elements.Length == 2 ? elements[0].NamedChildren.LastOrDefault() : null;
            var methodExpression = elements.Length == 2 ? elements[1].NamedChildren.LastOrDefault() : null;
            if (classExpression is null || methodExpression is null ||
                !TryReadClassConstant(document, classExpression, out className) ||
                document.Literal(methodExpression) is not { } literalMethod || !IsIdentifier(literalMethod))
                return false;
            method = literalMethod;
        }
        else return false;
        if (className is null || !project.Classes.TryGetValue(className, out var resolved) ||
            resolved.Kind != PhpTypeKind.Class || !resolved.Methods.Contains(method)) return false;
        listener = resolved;
        return true;
    }

    private static bool TryReadClassConstant(PhpDocument document, Node expression, out string? className)
    {
        className = null;
        if (expression.Type != "class_constant_access_expression" || expression.NamedChildren.Count != 2 ||
            !expression.NamedChildren[1].Text.Equals("class", StringComparison.OrdinalIgnoreCase)) return false;
        className = document.ResolveClassName(expression.NamedChildren[0]);
        return className is not null;
    }

    private static EventChannelReference EventChannel(PhpClassDeclaration declaration) =>
        new($"class:{declaration.FullyQualifiedName}", declaration.FullyQualifiedName,
            declaration.FullyQualifiedName);

    private static LaravelEventPublicationDetection Publication(
        EventChannelReference channel, PhpDocument document, Node call, string rule) =>
        new(channel.Key, channel.Name, channel.EventType, document.Path, document.Range(call), rule);

    private static LaravelEventSubscriptionDetection Subscription(
        EventChannelReference channel, PhpClassDeclaration listener, string method, PhpProjectModel project,
        PhpDocument document, Node source, string rule) =>
        new(channel.Key, channel.Name, channel.EventType, listener.FullyQualifiedName, method,
            PhpTypeRelations.IsAssignableTo(project, listener.FullyQualifiedName, ShouldQueue), document.Path,
            document.Range(source), rule);

    private static bool HasUnsupportedRegistrationContext(Node call)
    {
        for (var parent = call.Parent; parent is not null; parent = parent.Parent)
            if (parent.Type is "anonymous_function" or "arrow_function" or "function_definition" or
                "if_statement" or "switch_statement" or "while_statement" or "do_statement" or
                "for_statement" or "foreach_statement" or "conditional_expression" or "match_expression")
                return true;
        return false;
    }

    private static bool TryReadQueuedJob(PhpProjectModel project, PhpDocument document, Node expression,
        out PhpClassDeclaration job)
    {
        job = null!;
        if (expression.Type != "object_creation_expression") return false;
        var classNode = expression.NamedChildren.FirstOrDefault(item => item.Type is "name" or "qualified_name");
        var className = classNode is null ? null : document.ResolveClassName(classNode);
        if (className is null || !project.Classes.TryGetValue(className, out var resolved) ||
            resolved.Kind != PhpTypeKind.Class || !PhpTypeRelations.IsAssignableTo(project, className, ShouldQueue))
            return false;
        job = resolved;
        return true;
    }

    private static bool IsLaravelDispatchHelper(PhpDocument document, Node function) =>
        IsLaravelGlobalHelper(document, function, "dispatch");

    private static bool IsLaravelGlobalHelper(PhpDocument document, Node function, string helper)
    {
        var name = function.Text.Trim();
        if (name.StartsWith('\\')) return name[1..].Equals(helper, StringComparison.OrdinalIgnoreCase);
        if (!name.Equals(helper, StringComparison.OrdinalIgnoreCase) || document.CleanDescendants("function_definition")
                .Any(item => item.GetChildForField("name")?.Text.Equals(helper, StringComparison.OrdinalIgnoreCase) == true))
            return false;
        return !document.CleanDescendants("namespace_use_declaration")
            .Select(item => item.Text.Trim().TrimEnd(';'))
            .Where(item => item.StartsWith("use function ", StringComparison.OrdinalIgnoreCase))
            .Select(item => item[13..])
            .Any(item =>
            {
                var alias = item.LastIndexOf(" as ", StringComparison.OrdinalIgnoreCase);
                var importedName = alias >= 0 ? item[(alias + 4)..] : item.Split('\\').Last();
                return importedName.Equals(helper, StringComparison.OrdinalIgnoreCase);
            });
    }

    private static bool IsEventName(string value) =>
        value.Length is > 0 and <= 255 && value.All(character => !char.IsControl(character));

    private static bool IsIdentifier(string value) =>
        value.Length is > 0 and <= 255 && (char.IsLetter(value[0]) || value[0] == '_') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_');

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

    private static LaravelJobDispatchDetection Detection(
        PhpClassDeclaration job,
        PhpDocument document,
        Node call,
        string rule) =>
        new(job.FullyQualifiedName, job.Path, document.Path, document.Range(call), rule);

    private static Diagnostic Unsupported(PhpProjectModel project, PhpDocument document, Node call) =>
        new($"diagnostic:archie.php:php_laravel_job_unsupported:{Stable($"{document.Path}:{call.StartIndex}")}",
            "PHP_LARAVEL_JOB_UNSUPPORTED", "warning",
            $"Laravel job dispatch in '{document.Path}' uses a dynamic, unresolved, or non-queued job and produced no message channel.",
            project.Key);

    private static Diagnostic UnsupportedEvent(PhpProjectModel project, PhpDocument document, Node call) =>
        new($"diagnostic:archie.php:php_laravel_event_unsupported:{Stable($"{document.Path}:{call.StartIndex}")}",
            "PHP_LARAVEL_EVENT_UNSUPPORTED", "warning",
            $"Laravel event publication in '{document.Path}' uses a dynamic or unresolved event identity and produced no message channel.",
            project.Key);

    private static Diagnostic UnsupportedListener(PhpProjectModel project, PhpDocument document, Node source) =>
        new($"diagnostic:archie.php:php_laravel_listener_unsupported:{Stable($"{document.Path}:{source.StartIndex}")}",
            "PHP_LARAVEL_LISTENER_UNSUPPORTED", "warning",
            $"Laravel listener registration in '{document.Path}' uses a dynamic or unresolved event or listener identity and produced no subscription.",
            project.Key);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private sealed record CallArgument(string? Name, Node Value);
    private sealed record EventChannelReference(string Key, string Name, string? EventType);
}

internal sealed record LaravelMessagingScanResult(
    IReadOnlyList<LaravelJobDispatchDetection> JobDispatches,
    IReadOnlyList<Diagnostic> Diagnostics);

internal sealed record LaravelEventScanResult(
    IReadOnlyList<LaravelEventPublicationDetection> Publications,
    IReadOnlyList<LaravelEventSubscriptionDetection> Subscriptions,
    IReadOnlyList<Diagnostic> Diagnostics);
