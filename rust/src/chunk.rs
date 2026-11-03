use tree_sitter::{Language, Node, Parser};

const FUNC_TYPES: &[&str] = &[
    "function_definition",
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
    "method_declaration",
    "constructor_declaration",
    "function_item",
];
const CLASS_TYPES: &[&str] =
    &["class_definition", "class_declaration", "impl_item", "trait_item", "interface_declaration"];
const JS_DECLS: &[&str] = &["lexical_declaration", "variable_declaration"];
const JS_FUNC_VALUES: &[&str] = &["arrow_function", "function_expression", "function"];

pub const MAX_STORED_CHARS: usize = 6000;
const MODULE_FALLBACK_LINES: usize = 80;

pub struct Chunk {
    pub symbol: String,
    pub kind: &'static str,
    pub start_line: i32,
    pub end_line: i32,
    pub content: String,
}

/// Language label stored in the DB plus its tree-sitter grammar, keyed by file extension.
pub fn lang_for(ext: &str) -> Option<(&'static str, Language)> {
    Some(match ext {
        "py" => ("python", tree_sitter_python::LANGUAGE.into()),
        // TSX parses JavaScript and TypeScript too, so one grammar saves the size of two.
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "tsx" => ("tsx", tree_sitter_typescript::LANGUAGE_TSX.into()),
        "go" => ("go", tree_sitter_go::LANGUAGE.into()),
        "rs" => ("rust", tree_sitter_rust::LANGUAGE.into()),
        "java" => ("java", tree_sitter_java::LANGUAGE.into()),
        _ => return None,
    })
}

pub fn first_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn name_of(node: Node, field: &str, src: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .map(|n| String::from_utf8_lossy(&src[n.byte_range()]).into_owned())
}

fn qualify(scope: &[String], name: &str) -> String {
    scope.iter().map(String::as_str).chain([name]).collect::<Vec<_>>().join(".")
}

fn make(src: &[u8], range: Node, symbol: String, kind: &'static str) -> Chunk {
    Chunk {
        symbol,
        kind,
        start_line: range.start_position().row as i32 + 1,
        end_line: range.end_position().row as i32 + 1,
        content: first_chars(&String::from_utf8_lossy(&src[range.byte_range()]), MAX_STORED_CHARS),
    }
}

fn walk(node: Node, scope: &mut Vec<String>, src: &[u8], out: &mut Vec<Chunk>) {
    let t = node.kind();
    let kind = if scope.is_empty() { "function" } else { "method" };

    if t == "decorated_definition" {
        if let Some(inner) = node.child_by_field_name("definition") {
            if FUNC_TYPES.contains(&inner.kind()) {
                let name = name_of(inner, "name", src).unwrap_or_else(|| "?".into());
                out.push(make(src, node, qualify(scope, &name), kind));
            } else {
                walk(inner, scope, src, out);
            }
        }
        return;
    }
    if FUNC_TYPES.contains(&t) {
        let name = name_of(node, "name", src).unwrap_or_else(|| "?".into());
        out.push(make(src, node, qualify(scope, &name), kind));
        return;
    }
    if JS_DECLS.contains(&t) {
        let mut cursor = node.walk();
        for decl in node.named_children(&mut cursor) {
            let is_fn = decl
                .child_by_field_name("value")
                .is_some_and(|v| JS_FUNC_VALUES.contains(&v.kind()));
            if decl.kind() == "variable_declarator" && is_fn {
                let name = name_of(decl, "name", src).unwrap_or_else(|| "?".into());
                out.push(make(src, node, qualify(scope, &name), "function"));
                return;
            }
        }
        return;
    }
    if CLASS_TYPES.contains(&t) {
        // rust impl blocks name their target via the "type" field
        let name = name_of(node, "name", src)
            .or_else(|| name_of(node, "type", src))
            .unwrap_or_else(|| "?".into());
        scope.push(name);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, scope, src, out);
        }
        scope.pop();
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, scope, src, out);
    }
}

pub fn chunk_source(src: &[u8], language: &Language, filename: &str) -> Vec<Chunk> {
    let mut parser = Parser::new();
    if parser.set_language(language).is_err() {
        return vec![];
    }
    let Some(tree) = parser.parse(src, None) else { return vec![] };

    let mut out = Vec::new();
    walk(tree.root_node(), &mut Vec::new(), src, &mut out);

    if out.is_empty() {
        let text = String::from_utf8_lossy(src);
        let lines: Vec<&str> = text.lines().collect();
        let head = lines[..lines.len().min(MODULE_FALLBACK_LINES)].join("\n");
        if !head.trim().is_empty() {
            out.push(Chunk {
                symbol: filename.to_string(),
                kind: "module",
                start_line: 1,
                end_line: lines.len().clamp(1, MODULE_FALLBACK_LINES) as i32,
                content: first_chars(&head, MAX_STORED_CHARS),
            });
        }
    }
    out
}
