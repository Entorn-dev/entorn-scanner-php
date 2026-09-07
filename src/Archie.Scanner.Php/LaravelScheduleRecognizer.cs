using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelScheduleRecognizer
{
    private const string ScheduleFacade = "Illuminate\\Support\\Facades\\Schedule";
    private const string ScheduleType = "Illuminate\\Console\\Scheduling\\Schedule";
    private const string ConsoleKernel = "Illuminate\\Foundation\\Console\\Kernel";
    private const string ShouldQueue = "Illuminate\\Contracts\\Queue\\ShouldQueue";

    private static readonly IReadOnlyDictionary<string, (string Name, int? Seconds)> Frequencies =
        new Dictionary<string, (string, int?)>(StringComparer.OrdinalIgnoreCase)
        {
            ["everySecond"] = ("everySecond", 1),
            ["everyTwoSeconds"] = ("everyTwoSeconds", 2),
            ["everyFiveSeconds"] = ("everyFiveSeconds", 5),
            ["everyTenSeconds"] = ("everyTenSeconds", 10),
            ["everyFifteenSeconds"] = ("everyFifteenSeconds", 15),
            ["everyTwentySeconds"] = ("everyTwentySeconds", 20),
            ["everyThirtySeconds"] = ("everyThirtySeconds", 30),
            ["everyMinute"] = ("everyMinute", null),
            ["everyTwoMinutes"] = ("everyTwoMinutes", null),
            ["everyThreeMinutes"] = ("everyThreeMinutes", null),
            ["everyFourMinutes"] = ("everyFourMinutes", null),
            ["everyFiveMinutes"] = ("everyFiveMinutes", null),
            ["everyTenMinutes"] = ("everyTenMinutes", null),
            ["everyFifteenMinutes"] = ("everyFifteenMinutes", null),
            ["everyThirtyMinutes"] = ("everyThirtyMinutes", null),
            ["hourly"] = ("hourly", null),
            ["everyOddHour"] = ("everyOddHour", null),
            ["everyTwoHours"] = ("everyTwoHours", null),
            ["everyThreeHours"] = ("everyThreeHours", null),
            ["everyFourHours"] = ("everyFourHours", null),
            ["everySixHours"] = ("everySixHours", null),
            ["daily"] = ("daily", null),
            ["weekly"] = ("weekly", null),
            ["monthly"] = ("monthly", null),
            ["lastDayOfMonth"] = ("lastDayOfMonth", null),
            ["quarterly"] = ("quarterly", null),
            ["yearly"] = ("yearly", null)
        };

    private static readonly IReadOnlySet<string> DiscardedModifiers = new HashSet<string>(
        [
            "when", "skip", "between", "unlessBetween", "environments", "evenInMaintenanceMode",
            "withoutOverlapping", "onOneServer", "runInBackground", "before", "after", "onSuccess",
            "onFailure", "pingBefore", "thenPing", "pingOnSuccess", "pingOnFailure", "sendOutputTo",
            "appendOutputTo", "emailOutputTo", "emailWrittenOutputTo", "emailOutputOnFailure", "description",
            "name", "storeOutput", "user", "days", "weekdays", "weekends", "sundays", "mondays",
            "tuesdays", "wednesdays", "thursdays", "fridays", "saturdays", "onQueue", "onConnection"
        ], StringComparer.OrdinalIgnoreCase);

    public static LaravelScheduleScanResult Scan(PhpProjectModel project, CancellationToken cancellationToken)
    {
        var detections = new List<LaravelScheduleDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var terminal in document.CleanDescendants("scoped_call_expression")
                         .Concat(document.CleanDescendants("member_call_expression"))
                         .OrderBy(item => item.StartIndex))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var terminalName = terminal.GetChildForField("name")?.Text;
                if (terminalName is not ("command" or "job" or "call") ||
                    !IsScheduleTerminal(project, document, terminal)) continue;
                var outermost = OutermostChain(terminal);
                if (!TryReadArguments(terminal, out var arguments) ||
                    !TryReadTarget(project, document, terminalName, arguments, out var target) ||
                    !TryReadCadence(document, terminal, outermost, out var cadence))
                {
                    diagnostics.Add(Unsupported(project, document, outermost));
                    continue;
                }
                detections.Add(new(target.Kind, target.Key, target.Name, target.Type, target.Method, cadence,
                    document.Path, document.Range(outermost), $"laravel:schedule-{target.Rule}"));
            }
        }

        return new(
            detections.OrderBy(item => item.TargetKind).ThenBy(item => item.TargetKey, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal).ThenBy(item => item.Range.StartLine).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static bool IsScheduleTerminal(PhpProjectModel project, PhpDocument document, Node terminal)
    {
        if (terminal.Type == "scoped_call_expression")
            return terminal.GetChildForField("scope") is { } scope &&
                   string.Equals(document.ResolveClassName(scope), ScheduleFacade, StringComparison.OrdinalIgnoreCase);
        if (terminal.GetChildForField("object") is not { Type: "variable_name" } variable) return false;
        var method = Ancestors(terminal).FirstOrDefault(item => item.Type == "method_declaration");
        var classNode = Ancestors(terminal).FirstOrDefault(item => item.Type == "class_declaration");
        if (method?.GetChildForField("name")?.Text != "schedule" || classNode is null) return false;
        var declaration = project.Index.TypesByPath.GetValueOrDefault(document.Path)?.FirstOrDefault(item =>
            item.Kind == PhpTypeKind.Class && item.Range == document.Range(classNode));
        if (declaration is null ||
            !PhpTypeRelations.IsAssignableTo(project, declaration.FullyQualifiedName, ConsoleKernel)) return false;
        var parameters = method.NamedChildren.FirstOrDefault(item => item.Type == "formal_parameters");
        return parameters is not null && parameters.NamedChildren.Where(item => item.Type == "simple_parameter")
            .Any(item => item.GetChildForField("name")?.Text == variable.Text &&
                         item.GetChildForField("type") is { } type &&
                         string.Equals(document.ResolveClassName(type), ScheduleType, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryReadTarget(PhpProjectModel project, PhpDocument document, string terminal,
        IReadOnlyList<CallArgument> arguments, out ScheduleTarget target)
    {
        target = default!;
        var expression = FindArgument(arguments, terminal switch
        {
            "command" => "command",
            "job" => "job",
            _ => "callback"
        }, 0);
        if (expression is null) return false;
        if (terminal == "command" && document.Literal(expression) is { } command &&
            TryReadCommandName(command, out var commandName))
        {
            target = new(LaravelScheduleTargetKind.Command, commandName, commandName, null, null,
                "command");
            return true;
        }
        if (terminal == "job" && TryReadClass(project, document, expression, "handle", requireMethod: false,
                requireQueue: true, out var job))
        {
            target = new(LaravelScheduleTargetKind.Job, job.FullyQualifiedName, job.FullyQualifiedName,
                job.FullyQualifiedName, null, "job");
            return true;
        }
        if (terminal != "call") return false;
        if (expression.Type is "anonymous_function" or "arrow_function")
        {
            var range = document.Range(expression);
            target = new(LaravelScheduleTargetKind.Closure,
                $"{document.Path}:{range.StartLine}:{range.StartColumn}:{range.EndLine}:{range.EndColumn}",
                $"scheduled closure at {document.Path}:{range.StartLine}", null, null, "closure");
            return true;
        }
        if (TryReadCallback(project, document, expression, out var callback, out var method))
        {
            target = new(LaravelScheduleTargetKind.Callback, $"{callback.FullyQualifiedName}::{method}",
                $"{callback.FullyQualifiedName}::{method}", callback.FullyQualifiedName, method, "callback");
            return true;
        }
        return false;
    }

    private static bool TryReadCallback(PhpProjectModel project, PhpDocument document, Node expression,
        out PhpClassDeclaration callback, out string method)
    {
        callback = null!;
        method = "__invoke";
        if (expression.Type == "array_creation_expression")
        {
            var elements = expression.NamedChildren.Where(item => item.Type == "array_element_initializer").ToArray();
            var classExpression = elements.Length == 2 ? elements[0].NamedChildren.LastOrDefault() : null;
            var methodExpression = elements.Length == 2 ? elements[1].NamedChildren.LastOrDefault() : null;
            if (classExpression is null || methodExpression is null ||
                !TryReadClassConstant(document, classExpression, out var className) ||
                document.Literal(methodExpression) is not { } literalMethod || !IsIdentifier(literalMethod) ||
                className is null || !project.Classes.TryGetValue(className, out var resolved) ||
                resolved.Kind != PhpTypeKind.Class || !resolved.Methods.Contains(literalMethod)) return false;
            callback = resolved;
            method = literalMethod;
            return true;
        }
        return TryReadClass(project, document, expression, "__invoke", requireMethod: true,
            requireQueue: false, out callback);
    }

    private static bool TryReadClass(PhpProjectModel project, PhpDocument document, Node expression,
        string method, bool requireMethod, bool requireQueue, out PhpClassDeclaration declaration)
    {
        declaration = null!;
        string? className = null;
        if (expression.Type == "object_creation_expression")
        {
            var classNode = expression.NamedChildren.FirstOrDefault(item => item.Type is "name" or "qualified_name");
            if (classNode is not null) className = document.ResolveClassName(classNode);
        }
        else TryReadClassConstant(document, expression, out className);
        if (className is null || !project.Classes.TryGetValue(className, out var resolved) ||
            resolved.Kind != PhpTypeKind.Class || requireMethod && !resolved.Methods.Contains(method) ||
            requireQueue && !PhpTypeRelations.IsAssignableTo(project, className, ShouldQueue)) return false;
        declaration = resolved;
        return true;
    }

    private static bool TryReadCadence(PhpDocument document, Node terminal, Node outermost,
        out LaravelScheduleCadence cadence)
    {
        var kind = "frequency";
        string? expression = null;
        string? frequency = "everyMinute";
        int? intervalSeconds = null;
        string? timezone = null;
        var cadenceSet = false;
        for (var current = terminal; !SameNode(current, outermost);)
        {
            var modifier = current.Parent!;
            if (modifier.Type != "member_call_expression" ||
                modifier.GetChildForField("name")?.Text is not { } name ||
                !TryReadArguments(modifier, out var arguments))
            {
                cadence = default!;
                return false;
            }
            if (Frequencies.TryGetValue(name, out var normalized) && arguments.Count == 0 && !cadenceSet)
            {
                cadenceSet = true;
                kind = "frequency";
                frequency = normalized.Name;
                intervalSeconds = normalized.Seconds;
            }
            else if (name.Equals("cron", StringComparison.OrdinalIgnoreCase) && arguments.Count == 1 &&
                     !cadenceSet && document.Literal(arguments[0].Value) is { } cron && IsPrintable(cron))
            {
                cadenceSet = true;
                kind = "cron";
                expression = cron;
                frequency = null;
            }
            else if (name.Equals("timezone", StringComparison.OrdinalIgnoreCase) && arguments.Count == 1 &&
                     timezone is null && document.Literal(arguments[0].Value) is { } zone && IsPrintable(zone))
                timezone = zone;
            else if (!DiscardedModifiers.Contains(name))
            {
                cadence = default!;
                return false;
            }
            current = modifier;
        }
        cadence = new(kind, expression, frequency, intervalSeconds, timezone);
        return true;
    }

    private static bool TryReadCommandName(string value, out string name)
    {
        name = value.TrimStart().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return name.Length is > 0 and <= 255 && name.All(character =>
            char.IsLetterOrDigit(character) || character is '_' or '-' or '.' or ':');
    }

    private static bool IsPrintable(string value) =>
        value.Length is > 0 and <= 255 && value.All(character => !char.IsControl(character) && !char.IsSurrogate(character));

    private static bool IsIdentifier(string value) =>
        value.Length is > 0 and <= 255 && (char.IsLetter(value[0]) || value[0] == '_') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_');

    private static bool TryReadClassConstant(PhpDocument document, Node expression, out string? className)
    {
        className = null;
        if (expression.Type != "class_constant_access_expression" || expression.NamedChildren.Count != 2 ||
            !expression.NamedChildren[1].Text.Equals("class", StringComparison.OrdinalIgnoreCase)) return false;
        className = document.ResolveClassName(expression.NamedChildren[0]);
        return className is not null;
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

    private static Node OutermostChain(Node call)
    {
        var expression = call;
        while (expression.Parent is { Type: "member_call_expression" } parent &&
               SameNode(parent.GetChildForField("object"), expression)) expression = parent;
        return expression;
    }

    private static bool SameNode(Node? first, Node second) =>
        first is not null && first.StartIndex == second.StartIndex && first.EndIndex == second.EndIndex;

    private static IEnumerable<Node> Ancestors(Node node)
    {
        for (var parent = node.Parent; parent is not null; parent = parent.Parent) yield return parent;
    }

    private static Diagnostic Unsupported(PhpProjectModel project, PhpDocument document, Node call) =>
        new($"diagnostic:archie.php:php_laravel_schedule_unsupported:{Stable($"{document.Path}:{call.StartIndex}")}",
            "PHP_LARAVEL_SCHEDULE_UNSUPPORTED", "warning",
            $"Laravel schedule in '{document.Path}' uses a dynamic or unsupported target or cadence and produced no scheduled behavior.",
            project.Key);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private sealed record CallArgument(string? Name, Node Value);
    private sealed record ScheduleTarget(
        LaravelScheduleTargetKind Kind,
        string Key,
        string Name,
        string? Type,
        string? Method,
        string Rule);
}

internal sealed record LaravelScheduleScanResult(
    IReadOnlyList<LaravelScheduleDetection> Detections,
    IReadOnlyList<Diagnostic> Diagnostics);
