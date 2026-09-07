using System.Security.Cryptography;
using System.Text;
using TreeSitter;

namespace Archie.Scanner.Php;

internal static class LaravelEloquentRecognizer
{
    private const string EloquentModel = "Illuminate\\Database\\Eloquent\\Model";

    private static readonly IReadOnlyDictionary<string, string> Relations =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["belongsTo"] = "belongsTo",
            ["hasOne"] = "hasOne",
            ["hasMany"] = "hasMany",
            ["belongsToMany"] = "belongsToMany",
            ["morphTo"] = "morphTo",
            ["morphOne"] = "morphOne",
            ["morphMany"] = "morphMany"
        };

    public static LaravelEloquentScanResult Scan(PhpProjectModel project, CancellationToken cancellationToken)
    {
        var models = new List<LaravelEloquentModelDetection>();
        var relations = new List<LaravelEloquentRelationDetection>();
        var diagnostics = new List<Diagnostic>();
        foreach (var document in project.Documents.OrderBy(item => item.Path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var classNode in document.CleanDescendants("class_declaration"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var declaration = project.Index.TypesByPath.GetValueOrDefault(document.Path)?.FirstOrDefault(item =>
                    item.Kind == PhpTypeKind.Class && item.Range == document.Range(classNode));
                if (declaration is null ||
                    !PhpTypeRelations.IsAssignableTo(project, declaration.FullyQualifiedName, EloquentModel)) continue;

                var connection = ReadConnection(document, classNode);
                if (connection.Kind == ConnectionKind.Invalid)
                    diagnostics.Add(UnsupportedConnection(project, document, connection.Source!));
                else
                {
                    var isDefault = connection.Kind == ConnectionKind.Absent;
                    models.Add(new(declaration.FullyQualifiedName, declaration.Path, declaration.Range,
                        isDefault ? "default" : connection.Name!, isDefault,
                        isDefault ? Confidence.Inferred : Confidence.Confirmed,
                        isDefault ? "laravel:eloquent-default-connection" :
                            "laravel:eloquent-explicit-connection"));
                }

                ReadRelations(project, document, classNode, declaration, relations, diagnostics);
            }
        }
        return new(
            models.OrderBy(item => item.ModelType, StringComparer.Ordinal).ToArray(),
            relations.OrderBy(item => item.ModelType, StringComparer.Ordinal)
                .ThenBy(item => item.RelatedModelType, StringComparer.Ordinal)
                .ThenBy(item => item.Path, StringComparer.Ordinal).ThenBy(item => item.Range.StartLine).ToArray(),
            diagnostics.DistinctBy(item => item.Id).OrderBy(item => item.Id, StringComparer.Ordinal).ToArray());
    }

    private static ConnectionReference ReadConnection(PhpDocument document, Node classNode)
    {
        foreach (var property in DirectDeclarations(classNode).Where(item => item.Type == "property_declaration"))
            foreach (var element in property.NamedChildren.Where(item => item.Type == "property_element"))
            {
                if (element.NamedChildren.Count == 0 || element.NamedChildren[0].Text != "$connection") continue;
                if (element.NamedChildren.Count == 1 ||
                    element.NamedChildren.Count == 2 && element.NamedChildren[1].Text.Equals("null",
                        StringComparison.OrdinalIgnoreCase)) return new(ConnectionKind.Absent, null, element);
                if (element.NamedChildren.Count == 2 && document.Literal(element.NamedChildren[1]) is { } literal &&
                    IsConnectionName(literal)) return new(ConnectionKind.Explicit, literal, element);
                return new(ConnectionKind.Invalid, null, element);
            }
        return new(ConnectionKind.Absent, null, null);
    }

    private static void ReadRelations(
        PhpProjectModel project,
        PhpDocument document,
        Node classNode,
        PhpClassDeclaration model,
        ICollection<LaravelEloquentRelationDetection> relations,
        ICollection<Diagnostic> diagnostics)
    {
        foreach (var method in DirectDeclarations(classNode).Where(item => item.Type == "method_declaration"))
            foreach (var returnNode in Descendants(method).Where(item => item.Type == "return_statement" &&
                         !HasNestedCallable(item, method)))
            {
                var call = returnNode.NamedChildren.FirstOrDefault();
                if (call?.Type != "member_call_expression" ||
                    call.GetChildForField("object") is not { Type: "variable_name", Text: "$this" } ||
                    call.GetChildForField("name")?.Text is not { } relation ||
                    !Relations.TryGetValue(relation, out var normalizedRelation)) continue;
                if (!TryReadArguments(call, out var arguments))
                {
                    diagnostics.Add(UnsupportedRelation(project, document, call));
                    continue;
                }
                if (relation.Equals("morphTo", StringComparison.OrdinalIgnoreCase) && arguments.Count == 0) continue;
                if (arguments.Count == 0 ||
                    !TryReadClassConstant(document, arguments[0], out var relatedType) || relatedType is null ||
                    !project.Classes.TryGetValue(relatedType, out var related) || related.Kind != PhpTypeKind.Class ||
                    !PhpTypeRelations.IsAssignableTo(project, relatedType, EloquentModel))
                {
                    diagnostics.Add(UnsupportedRelation(project, document, call));
                    continue;
                }
                relations.Add(new(model.FullyQualifiedName, related.FullyQualifiedName,
                    normalizedRelation,
                    document.Path, document.Range(call), "laravel:eloquent-model-relation"));
            }
    }

    private static bool HasNestedCallable(Node node, Node method)
    {
        for (var parent = node.Parent; parent is not null && !SameNode(parent, method); parent = parent.Parent)
            if (parent.Type is "anonymous_function" or "arrow_function" or "function_definition" or
                "anonymous_class" or "class_declaration") return true;
        return false;
    }

    private static IEnumerable<Node> DirectDeclarations(Node classNode) =>
        classNode.NamedChildren.Where(item => item.Type == "declaration_list").SelectMany(item => item.NamedChildren);

    private static IEnumerable<Node> Descendants(Node root)
    {
        var pending = new Stack<Node>();
        foreach (var child in root.NamedChildren.Reverse()) pending.Push(child);
        while (pending.Count > 0)
        {
            var node = pending.Pop();
            yield return node;
            foreach (var child in node.NamedChildren.Reverse()) pending.Push(child);
        }
    }

    private static bool TryReadArguments(Node call, out IReadOnlyList<Node> arguments)
    {
        var container = call.GetChildForField("arguments");
        if (container is null) { arguments = []; return false; }
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

    private static bool TryReadClassConstant(PhpDocument document, Node expression, out string? className)
    {
        className = null;
        if (expression.Type != "class_constant_access_expression" || expression.NamedChildren.Count != 2 ||
            !expression.NamedChildren[1].Text.Equals("class", StringComparison.OrdinalIgnoreCase)) return false;
        className = document.ResolveClassName(expression.NamedChildren[0]);
        return className is not null;
    }

    private static bool IsConnectionName(string value) =>
        value.Length is > 0 and <= 128 && value.All(character =>
            char.IsLetterOrDigit(character) || character is '_' or '-' or '.');

    private static bool SameNode(Node first, Node second) =>
        first.StartIndex == second.StartIndex && first.EndIndex == second.EndIndex;

    private static Diagnostic UnsupportedConnection(PhpProjectModel project, PhpDocument document, Node source) =>
        new($"diagnostic:archie.php:php_laravel_eloquent_connection_unsupported:" +
            Stable($"{document.Path}:{source.StartIndex}"),
            "PHP_LARAVEL_ELOQUENT_CONNECTION_UNSUPPORTED", "warning",
            $"Eloquent model in '{document.Path}' declares a dynamic or unsupported connection and produced no database dependency.",
            project.Key);

    private static Diagnostic UnsupportedRelation(PhpProjectModel project, PhpDocument document, Node source) =>
        new($"diagnostic:archie.php:php_laravel_eloquent_relation_unsupported:" +
            Stable($"{document.Path}:{source.StartIndex}"),
            "PHP_LARAVEL_ELOQUENT_RELATION_UNSUPPORTED", "warning",
            $"Eloquent relation in '{document.Path}' uses a dynamic or unresolved related model and produced no module dependency.",
            project.Key);

    private static string Stable(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];

    private enum ConnectionKind { Absent, Explicit, Invalid }
    private sealed record ConnectionReference(ConnectionKind Kind, string? Name, Node? Source);
}

internal sealed record LaravelEloquentScanResult(
    IReadOnlyList<LaravelEloquentModelDetection> Models,
    IReadOnlyList<LaravelEloquentRelationDetection> Relations,
    IReadOnlyList<Diagnostic> Diagnostics);
