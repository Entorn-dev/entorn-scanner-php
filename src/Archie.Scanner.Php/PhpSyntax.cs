using TreeSitter;

namespace Archie.Scanner.Php;

internal sealed record PhpSyntaxValidation(bool HasErrors, SourceRange Range, int NodeCount);

internal sealed class PhpDocument : IDisposable
{
    private readonly Tree tree;

    public PhpDocument(string path, Tree tree)
    {
        Path = path;
        this.tree = tree;
        Namespace = ReadNamespace(tree.RootNode);
        Imports = ReadImports(tree.RootNode);
        Classes = ReadClasses(tree.RootNode);
    }

    public string Path { get; }
    public string? Namespace { get; }
    public IReadOnlyDictionary<string, string> Imports { get; }
    public IReadOnlyList<PhpClassDeclaration> Classes { get; }

    public IReadOnlyList<Node> CleanDescendants(string nodeType) =>
        Descendants(tree.RootNode).Where(node => node.Type == nodeType && !node.HasError && !node.IsMissing).ToArray();

    public string? Literal(Node node)
    {
        var text = node.Text;
        if (text.Length < 2 || text.Length > 4096) return null;
        if (text[0] == '"' && text[^1] == '"')
        {
            var value = text[1..^1];
            return value.Contains('$') || value.Contains('\\')
                ? null
                : value;
        }

        if (text[0] != '\'' || text[^1] != '\'') return null;
        var result = new System.Text.StringBuilder(text.Length - 2);
        for (var index = 1; index < text.Length - 1; index++)
        {
            if (text[index] != '\\')
            {
                result.Append(text[index]);
                continue;
            }

            if (++index >= text.Length - 1) return null;
            if (text[index] is not ('\\' or '\'')) result.Append('\\');
            result.Append(text[index]);
        }
        return result.ToString();
    }

    public string? ResolveClassName(Node node) => ResolveClassName(node.Text);

    public string? ResolveClassName(string text)
    {
        var name = NormalizeClassName(text);
        if (name is null || name.Equals("self", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("static", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("parent", StringComparison.OrdinalIgnoreCase))
            return null;
        if (text.TrimStart().StartsWith('\\')) return name;
        if (name.StartsWith("namespace\\", StringComparison.OrdinalIgnoreCase))
            return Qualify(Namespace, name[10..]);

        var separator = name.IndexOf('\\');
        var first = separator < 0 ? name : name[..separator];
        if (Imports.TryGetValue(first, out var imported))
            return separator < 0 ? imported : $"{imported}\\{name[(separator + 1)..]}";
        return Qualify(Namespace, name);
    }

    public SourceRange Range(Node node) => ToRange(node);

    public void Dispose() => tree.Dispose();

    private string? ReadNamespace(Node root)
    {
        var declarations = Descendants(root).Where(node => node.Type == "namespace_definition").ToArray();
        if (declarations.Length != 1) return null;
        var name = declarations[0].GetChildForField("name");
        return name is null ? null : NormalizeClassName(name.Text);
    }

    private static IReadOnlyDictionary<string, string> ReadImports(Node root)
    {
        var imports = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ambiguousAliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var clause in Descendants(root).Where(node => node.Type == "namespace_use_clause"))
        {
            var text = clause.Text.Trim();
            var declaration = clause.Parent?.Text.TrimStart();
            if (text.Contains('{') || declaration?.StartsWith("use function ", StringComparison.OrdinalIgnoreCase) == true ||
                declaration?.StartsWith("use const ", StringComparison.OrdinalIgnoreCase) == true)
                continue;

            string className;
            string alias;
            var aliasIndex = text.LastIndexOf(" as ", StringComparison.OrdinalIgnoreCase);
            if (aliasIndex >= 0)
            {
                className = text[..aliasIndex].Trim();
                alias = text[(aliasIndex + 4)..].Trim();
            }
            else
            {
                className = text;
                alias = text.Split('\\').Last();
            }

            var normalized = NormalizeClassName(className);
            if (normalized is null || !IsIdentifier(alias) || ambiguousAliases.Contains(alias)) continue;
            if (!imports.TryAdd(alias, normalized))
            {
                imports.Remove(alias);
                ambiguousAliases.Add(alias);
            }
        }
        return imports;
    }

    private IReadOnlyList<PhpClassDeclaration> ReadClasses(Node root)
    {
        var result = new List<PhpClassDeclaration>();
        foreach (var declaration in Descendants(root).Where(node =>
                     node.Type is "class_declaration" or "interface_declaration" or "trait_declaration" or
                         "enum_declaration"))
        {
            var name = declaration.GetChildForField("name")?.Text;
            if (!IsIdentifier(name)) continue;
            var methods = declaration.NamedChildren.Where(node => node.Type == "declaration_list")
                .SelectMany(node => node.NamedChildren)
                .Where(node => node.Type == "method_declaration")
                .Select(node => node.GetChildForField("name")?.Text)
                .Where(IsIdentifier)
                .Select(item => item!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var baseTypes = declaration.NamedChildren
                .Where(node => node.Type is "base_clause" or "class_interface_clause")
                .SelectMany(node => node.NamedChildren)
                .Select(ResolveClassName)
                .Where(item => item is not null)
                .Select(item => item!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var traits = declaration.NamedChildren.Where(node => node.Type == "declaration_list")
                .SelectMany(node => node.NamedChildren)
                .Where(node => node.Type == "use_declaration")
                .SelectMany(node => node.NamedChildren)
                .Where(node => node.Type is "name" or "qualified_name")
                .Select(ResolveClassName)
                .Where(item => item is not null)
                .Select(item => item!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            result.Add(new(TypeKind(declaration.Type), Qualify(Namespace, name!), Path, ToRange(declaration),
                baseTypes, methods, traits));
        }
        return result;
    }

    private static PhpTypeKind TypeKind(string nodeType) => nodeType switch
    {
        "interface_declaration" => PhpTypeKind.Interface,
        "trait_declaration" => PhpTypeKind.Trait,
        "enum_declaration" => PhpTypeKind.Enum,
        _ => PhpTypeKind.Class
    };

    private static IEnumerable<Node> Descendants(Node root)
    {
        var stack = new Stack<Node>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            yield return node;
            for (var index = node.NamedChildren.Count - 1; index >= 0; index--)
                stack.Push(node.NamedChildren[index]);
        }
    }

    private static string Qualify(string? namespaceName, string name) =>
        string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}\\{name}";

    private static string? NormalizeClassName(string text)
    {
        var value = text.Trim().TrimStart('\\');
        if (value.Length == 0 || value.Length > 1024) return null;
        return value.Split('\\').All(IsIdentifier) ? value : null;
    }

    private static bool IsIdentifier(string? value) =>
        !string.IsNullOrEmpty(value) && (char.IsLetter(value[0]) || value[0] == '_' || value[0] >= '\u0080') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_' || character >= '\u0080');

    internal static SourceRange ToRange(Node node) =>
        new(node.StartPosition.Row + 1, node.StartPosition.Column + 1,
            node.EndPosition.Row + 1, node.EndPosition.Column + 1);
}

internal sealed class PhpSyntax : IDisposable
{
    private readonly Language language;
    private readonly Parser parser;

    public PhpSyntax()
    {
        language = new("PHP");
        parser = new(language);
    }

    public PhpSyntaxValidation Validate(
        string source,
        PhpScannerLimits limits,
        ref int aggregateSyntaxNodes,
        CancellationToken cancellationToken)
    {
        var (tree, validation) = ParseTree("PHP input", source, limits, ref aggregateSyntaxNodes, cancellationToken);
        tree.Dispose();
        return validation;
    }

    public (PhpDocument? Document, PhpSyntaxValidation Validation) ParseDocument(
        string path,
        string source,
        PhpScannerLimits limits,
        ref int aggregateSyntaxNodes,
        CancellationToken cancellationToken)
    {
        var (tree, validation) = ParseTree(path, source, limits, ref aggregateSyntaxNodes, cancellationToken);
        if (validation.HasErrors)
        {
            tree.Dispose();
            return (null, validation);
        }
        try
        {
            return (new(path, tree), validation);
        }
        catch
        {
            tree.Dispose();
            throw;
        }
    }

    private (Tree Tree, PhpSyntaxValidation Validation) ParseTree(
        string path,
        string source,
        PhpScannerLimits limits,
        ref int aggregateSyntaxNodes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var tree = parser.Parse(source)
            ?? throw new InvalidDataException("The PHP parser did not return a syntax tree.");
        try
        {
            var root = tree.RootNode;
            var nodes = 0;
            var stack = new Stack<(Node Node, int Depth)>();
            stack.Push((root, 1));
            while (stack.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (node, depth) = stack.Pop();
                nodes++;
                if (nodes > limits.MaxSyntaxNodesPerFile)
                    throw new PhpWorkerLimitException("PHP_SYNTAX_NODE_LIMIT_EXCEEDED",
                        $"Eligible PHP input '{path}' exceeded the per-file syntax-node budget " +
                        $"({nodes} nodes observed; limit {limits.MaxSyntaxNodesPerFile}).");
                if (aggregateSyntaxNodes + nodes > limits.MaxSyntaxNodes)
                    throw new PhpWorkerLimitException("PHP_SYNTAX_NODE_LIMIT_EXCEEDED",
                        $"Eligible PHP input '{path}' exceeded the aggregate syntax-node budget " +
                        $"({aggregateSyntaxNodes} prior nodes plus {nodes} current nodes observed; " +
                        $"limit {limits.MaxSyntaxNodes}).");
                if (depth > limits.MaxSyntaxDepth)
                    throw new PhpWorkerLimitException("PHP_SYNTAX_DEPTH_LIMIT_EXCEEDED",
                        "The PHP scanner exceeded its bounded syntax-depth budget.");
                for (var index = node.Children.Count - 1; index >= 0; index--)
                    stack.Push((node.Children[index], depth + 1));
            }

            aggregateSyntaxNodes += nodes;
            parser.Reset();
            return (tree, new(root.HasError, PhpDocument.ToRange(root), nodes));
        }
        catch
        {
            tree.Dispose();
            parser.Reset();
            throw;
        }
    }

    public void Dispose()
    {
        parser.Dispose();
        language.Dispose();
    }
}
