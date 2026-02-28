//! AST-based code validator for the Forge sandbox.
//!
//! Uses `oxc_parser` to parse LLM-generated JavaScript into an AST and walks
//! the tree to detect sandbox escape patterns. This closes the entire class of
//! syntactic bypass vectors that the regex validator cannot catch (computed
//! property access, tagged templates, indirect eval via constructor chains, etc).
//!
//! This module is only compiled when the `ast-validator` feature is enabled.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Maximum nesting depth before we reject the code.
/// Prevents parser stack overflow on deeply nested input.
const MAX_NESTING_DEPTH: usize = 256;

/// Errors detected by the AST validator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AstViolation {
    /// Parser could not parse the code.
    ParseError(String),
    /// Code exceeds maximum nesting depth (prevents parser stack overflow).
    NestingTooDeep {
        /// Maximum allowed nesting depth.
        max: usize,
        /// Actual detected nesting depth.
        actual: usize,
    },
    /// A banned AST pattern was detected.
    BannedPattern {
        /// Human-readable description of the violation.
        description: String,
    },
}

impl std::fmt::Display for AstViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
            Self::NestingTooDeep { max, actual } => {
                write!(f, "nesting depth {actual} exceeds maximum {max}")
            }
            Self::BannedPattern { description } => write!(f, "{description}"),
        }
    }
}

/// Check nesting depth of brackets/braces/parens BEFORE parsing.
/// This prevents parser stack overflow attacks with deeply nested code.
pub fn check_nesting_depth(code: &str) -> Result<(), AstViolation> {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    for ch in code.chars() {
        match ch {
            '{' | '[' | '(' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            '}' | ']' | ')' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    if max_depth > MAX_NESTING_DEPTH {
        return Err(AstViolation::NestingTooDeep {
            max: MAX_NESTING_DEPTH,
            actual: max_depth,
        });
    }
    Ok(())
}

/// Validate code by parsing to AST and walking for banned patterns.
///
/// Returns `Ok(())` if the code is safe, or `Err(AstViolation)` describing
/// the first violation found.
pub fn validate_ast(code: &str) -> Result<(), AstViolation> {
    // 1. Pre-scan nesting depth
    check_nesting_depth(code)?;

    // 2. Parse
    let allocator = Allocator::default();
    let source_type = SourceType::mjs();
    let ret = Parser::new(&allocator, code, source_type).parse();

    if ret.panicked {
        return Err(AstViolation::ParseError(
            "parser panicked on malformed input".into(),
        ));
    }

    // We don't reject on parse errors alone — partial ASTs can still contain
    // dangerous patterns we want to catch. But if there's no body at all, reject.
    if ret.program.body.is_empty() && !ret.errors.is_empty() {
        return Err(AstViolation::ParseError(
            ret.errors
                .first()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown parse error".into()),
        ));
    }

    // 3. Walk AST
    let mut walker = AstWalker { violations: vec![] };
    for stmt in &ret.program.body {
        walker.walk_statement(stmt);
        if !walker.violations.is_empty() {
            return Err(walker.violations.remove(0));
        }
    }

    Ok(())
}

/// Recursive AST walker that collects security violations.
struct AstWalker {
    violations: Vec<AstViolation>,
}

impl AstWalker {
    fn report(&mut self, description: impl Into<String>) {
        self.violations.push(AstViolation::BannedPattern {
            description: description.into(),
        });
    }

    fn has_violation(&self) -> bool {
        !self.violations.is_empty()
    }

    // --- Expression checks ---

    fn check_identifier(&mut self, name: &str) {
        match name {
            // Note: eval as a bare identifier is NOT flagged (e.g. `typeof eval` is a
            // safe runtime check). Only `eval(...)` calls are caught in check_call_callee.
            "Proxy" => self.report("Proxy constructor is banned in the sandbox"),
            "Reflect" => self.report("Reflect API is banned in the sandbox"),
            "WebAssembly" => self.report("WebAssembly is banned in the sandbox"),
            _ => {}
        }
    }

    /// Check if an expression is a dangerous identifier (eval, Function, etc.)
    /// in call position.
    fn check_call_callee(&mut self, callee: &Expression<'_>) {
        match callee {
            // Direct: eval(...), Function(...), Proxy(...)
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();
                match name {
                    "eval" => self.report(
                        "eval() call — the sandbox has no eval. Use forge.callTool() to interact with external services.",
                    ),
                    "Function" => self.report(
                        "Function() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "AsyncFunction" => self.report(
                        "AsyncFunction() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "GeneratorFunction" => self.report(
                        "GeneratorFunction() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "Proxy" => self.report("Proxy() constructor is banned in the sandbox"),
                    _ => {}
                }
            }
            // Reflect.construct(...)
            Expression::StaticMemberExpression(member) => {
                if let Expression::Identifier(obj) = &member.object {
                    let obj_name = obj.name.as_str();
                    let prop_name = member.property.name.as_str();

                    match (obj_name, prop_name) {
                        ("Reflect", "construct") => {
                            self.report("Reflect.construct() is banned in the sandbox")
                        }
                        ("Reflect", _) => self.report("Reflect API is banned in the sandbox"),
                        ("String", "fromCharCode") => self.report(
                            "String.fromCharCode() is banned — potential code construction",
                        ),
                        ("String", "raw") => self.report(
                            "String.raw tagged template is banned — potential code generation",
                        ),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Check for dangerous static member expressions like __proto__, constructor.constructor,
    /// Deno.*, process.env, etc.
    fn check_static_member(&mut self, expr: &StaticMemberExpression<'_>) {
        let prop = expr.property.name.as_str();

        // __proto__ access
        if prop == "__proto__" {
            self.report("__proto__ access is banned — prototype pollution vector");
            return;
        }

        // obj.constructor.constructor (Function constructor escape)
        if prop == "constructor" {
            if let Expression::StaticMemberExpression(inner) = &expr.object {
                if inner.property.name.as_str() == "constructor" {
                    self.report(
                        "constructor.constructor chain is banned — Function constructor escape",
                    );
                    return;
                }
            }
        }

        // Deno.* access
        if let Expression::Identifier(obj) = &expr.object {
            let obj_name = obj.name.as_str();
            match obj_name {
                "Deno" => {
                    self.report("Deno.* access is banned in the sandbox");
                }
                // Note: globalThis.prop (static member) is NOT blocked — only
                // globalThis[expr] (computed member) is dangerous. Static access
                // like `typeof globalThis.eval` is just a runtime check.
                "Symbol" => match prop {
                    "toPrimitive" => {
                        self.report("Symbol.toPrimitive is banned — type confusion attack vector");
                    }
                    "hasInstance" => {
                        self.report("Symbol.hasInstance is banned — type confusion attack vector");
                    }
                    _ => {}
                },
                "process" => match prop {
                    "env" | "exit" | "argv" | "stdin" | "stdout" | "stderr" | "kill"
                    | "binding" => {
                        self.report(format!("process.{prop} access is banned in the sandbox"));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    /// Check computed member expressions: obj["constructor"], obj[Symbol.toPrimitive], etc.
    fn check_computed_member(&mut self, expr: &ComputedMemberExpression<'_>) {
        match &expr.expression {
            // obj["constructor"] — string literal computed access to dangerous props
            Expression::StringLiteral(lit) => {
                let val = lit.value.as_str();
                match val {
                    "constructor" => {
                        self.report(
                            "computed [\"constructor\"] access is banned — prototype escape vector",
                        );
                    }
                    "__proto__" => {
                        self.report("computed [\"__proto__\"] access is banned — prototype pollution vector");
                    }
                    "eval" => {
                        self.report("computed [\"eval\"] access is banned — indirect eval vector");
                    }
                    _ => {}
                }
            }
            // obj[Symbol.toPrimitive] or obj[Symbol.hasInstance]
            Expression::StaticMemberExpression(member) => {
                if let Expression::Identifier(obj) = &member.object {
                    if obj.name.as_str() == "Symbol" {
                        let prop = member.property.name.as_str();
                        match prop {
                            "toPrimitive" => {
                                self.report(
                                    "Symbol.toPrimitive is banned — type confusion attack vector",
                                );
                            }
                            "hasInstance" => {
                                self.report(
                                    "Symbol.hasInstance is banned — type confusion attack vector",
                                );
                            }
                            _ => {}
                        }
                    }
                }
                // Also check for globalThis[...] pattern
                if let Expression::Identifier(obj) = &expr.object {
                    if obj.name.as_str() == "globalThis" {
                        self.report("globalThis[...] computed access is banned in the sandbox");
                    }
                }
            }
            // globalThis[anything] — dynamic global access (non-literal, non-member expression)
            _ => {
                if let Expression::Identifier(obj) = &expr.object {
                    if obj.name.as_str() == "globalThis" {
                        self.report("globalThis[...] computed access is banned in the sandbox");
                    }
                }
            }
        }
    }

    /// Check tagged template expressions: String.raw`...`
    fn check_tagged_template(&mut self, expr: &TaggedTemplateExpression<'_>) {
        if let Expression::StaticMemberExpression(member) = &expr.tag {
            if let Expression::Identifier(obj) = &member.object {
                if obj.name.as_str() == "String" && member.property.name.as_str() == "raw" {
                    self.report("String.raw tagged template is banned — potential code generation");
                }
            }
        }
    }

    /// Check import.meta
    fn check_meta_property(&mut self, expr: &MetaProperty<'_>) {
        if expr.meta.name.as_str() == "import" && expr.property.name.as_str() == "meta" {
            self.report("import.meta is banned in the sandbox");
        }
    }

    // --- Walk methods ---

    fn walk_statement(&mut self, stmt: &Statement<'_>) {
        if self.has_violation() {
            return;
        }
        match stmt {
            Statement::ExpressionStatement(es) => self.walk_expression(&es.expression),
            Statement::BlockStatement(block) => {
                for s in &block.body {
                    self.walk_statement(s);
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Statement::IfStatement(ifs) => {
                self.walk_expression(&ifs.test);
                if self.has_violation() {
                    return;
                }
                self.walk_statement(&ifs.consequent);
                if let Some(alt) = &ifs.alternate {
                    if self.has_violation() {
                        return;
                    }
                    self.walk_statement(alt);
                }
            }
            Statement::ReturnStatement(ret) => {
                if let Some(arg) = &ret.argument {
                    self.walk_expression(arg);
                }
            }
            Statement::VariableDeclaration(decl) => {
                for declarator in &decl.declarations {
                    if let Some(init) = &declarator.init {
                        self.walk_expression(init);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
            }
            Statement::ForStatement(fors) => {
                if let Some(init) = &fors.init {
                    match init {
                        ForStatementInit::VariableDeclaration(decl) => {
                            for declarator in &decl.declarations {
                                if let Some(init) = &declarator.init {
                                    self.walk_expression(init);
                                    if self.has_violation() {
                                        return;
                                    }
                                }
                            }
                        }
                        _ => {
                            if let Some(expr) = init.as_expression() {
                                self.walk_expression(expr);
                                if self.has_violation() {
                                    return;
                                }
                            }
                        }
                    }
                }
                if let Some(test) = &fors.test {
                    self.walk_expression(test);
                    if self.has_violation() {
                        return;
                    }
                }
                if let Some(update) = &fors.update {
                    self.walk_expression(update);
                    if self.has_violation() {
                        return;
                    }
                }
                self.walk_statement(&fors.body);
            }
            Statement::ForInStatement(fis) => {
                self.walk_expression(&fis.right);
                if self.has_violation() {
                    return;
                }
                self.walk_statement(&fis.body);
            }
            Statement::ForOfStatement(fos) => {
                self.walk_expression(&fos.right);
                if self.has_violation() {
                    return;
                }
                self.walk_statement(&fos.body);
            }
            Statement::WhileStatement(ws) => {
                self.walk_expression(&ws.test);
                if self.has_violation() {
                    return;
                }
                self.walk_statement(&ws.body);
            }
            Statement::DoWhileStatement(dws) => {
                self.walk_statement(&dws.body);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&dws.test);
            }
            Statement::WithStatement(_) => {
                self.report("with statement is banned in the sandbox");
            }
            Statement::SwitchStatement(ss) => {
                self.walk_expression(&ss.discriminant);
                if self.has_violation() {
                    return;
                }
                for case in &ss.cases {
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                        if self.has_violation() {
                            return;
                        }
                    }
                    for s in &case.consequent {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
            }
            Statement::TryStatement(ts) => {
                for s in &ts.block.body {
                    self.walk_statement(s);
                    if self.has_violation() {
                        return;
                    }
                }
                if let Some(handler) = &ts.handler {
                    for s in &handler.body.body {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
                if let Some(finalizer) = &ts.finalizer {
                    for s in &finalizer.body {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
            }
            Statement::ThrowStatement(ts) => {
                self.walk_expression(&ts.argument);
            }
            Statement::LabeledStatement(ls) => {
                self.walk_statement(&ls.body);
            }
            // Declarations that may contain expressions
            Statement::FunctionDeclaration(fd) => {
                if let Some(body) = &fd.body {
                    for s in &body.statements {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
            }
            Statement::ClassDeclaration(cd) => {
                self.walk_class_body(&cd.body);
            }
            // Skip: BreakStatement, ContinueStatement, EmptyStatement, DebuggerStatement
            _ => {}
        }
    }

    fn walk_class_body(&mut self, body: &ClassBody<'_>) {
        for element in &body.body {
            match element {
                ClassElement::MethodDefinition(md) => {
                    if let Some(body) = &md.value.body {
                        for s in &body.statements {
                            self.walk_statement(s);
                            if self.has_violation() {
                                return;
                            }
                        }
                    }
                }
                ClassElement::PropertyDefinition(pd) => {
                    if let Some(val) = &pd.value {
                        self.walk_expression(val);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
                ClassElement::StaticBlock(sb) => {
                    for s in &sb.body {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn walk_expression(&mut self, expr: &Expression<'_>) {
        if self.has_violation() {
            return;
        }
        match expr {
            Expression::Identifier(ident) => {
                self.check_identifier(ident.name.as_str());
            }
            Expression::CallExpression(call) => {
                self.check_call_callee(&call.callee);
                if self.has_violation() {
                    return;
                }
                // Walk callee expression (for nested patterns)
                self.walk_expression(&call.callee);
                if self.has_violation() {
                    return;
                }
                // Walk arguments
                for arg in &call.arguments {
                    match arg {
                        Argument::SpreadElement(spread) => {
                            self.walk_expression(&spread.argument);
                        }
                        _ => {
                            if let Some(expr) = arg.as_expression() {
                                self.walk_expression(expr);
                            }
                        }
                    }
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::NewExpression(new_expr) => {
                // new Function(...), new Proxy(...), new WebAssembly.Module(...)
                self.check_new_callee(&new_expr.callee);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&new_expr.callee);
                if self.has_violation() {
                    return;
                }
                for arg in &new_expr.arguments {
                    match arg {
                        Argument::SpreadElement(spread) => {
                            self.walk_expression(&spread.argument);
                        }
                        _ => {
                            if let Some(expr) = arg.as_expression() {
                                self.walk_expression(expr);
                            }
                        }
                    }
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::StaticMemberExpression(member) => {
                self.check_static_member(member);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&member.object);
            }
            Expression::ComputedMemberExpression(member) => {
                self.check_computed_member(member);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&member.object);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&member.expression);
            }
            Expression::TaggedTemplateExpression(tagged) => {
                self.check_tagged_template(tagged);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&tagged.tag);
                // Walk template expressions
                for expr in &tagged.quasi.expressions {
                    self.walk_expression(expr);
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::MetaProperty(meta) => {
                self.check_meta_property(meta);
            }
            Expression::ImportExpression(imp) => {
                self.report("dynamic import() is banned in the sandbox");
                // Still walk to catch nested issues
                let _ = imp;
            }
            Expression::ArrowFunctionExpression(arrow) => {
                if let Some(body) = &arrow.body.statements.first() {
                    // Walk all statements in body
                    for s in &arrow.body.statements {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                    let _ = body;
                }
            }
            Expression::FunctionExpression(func) => {
                if let Some(body) = &func.body {
                    for s in &body.statements {
                        self.walk_statement(s);
                        if self.has_violation() {
                            return;
                        }
                    }
                }
            }
            Expression::AssignmentExpression(assign) => {
                self.walk_expression(&assign.right);
                // Check if assigning to dangerous targets via member expressions
                if let Some(member) = assign.left.as_member_expression() {
                    match member {
                        MemberExpression::StaticMemberExpression(m) => {
                            self.check_static_member(m);
                            if !self.has_violation() {
                                self.walk_expression(&m.object);
                            }
                        }
                        MemberExpression::ComputedMemberExpression(m) => {
                            self.check_computed_member(m);
                            if !self.has_violation() {
                                self.walk_expression(&m.object);
                            }
                        }
                        MemberExpression::PrivateFieldExpression(pf) => {
                            self.walk_expression(&pf.object);
                        }
                    }
                }
            }
            Expression::BinaryExpression(bin) => {
                self.walk_expression(&bin.left);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&bin.right);
            }
            Expression::LogicalExpression(log) => {
                self.walk_expression(&log.left);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&log.right);
            }
            Expression::ConditionalExpression(cond) => {
                self.walk_expression(&cond.test);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&cond.consequent);
                if self.has_violation() {
                    return;
                }
                self.walk_expression(&cond.alternate);
            }
            Expression::UnaryExpression(unary) => {
                self.walk_expression(&unary.argument);
            }
            Expression::UpdateExpression(_update) => {
                // UpdateExpression argument is a SimpleAssignmentTarget, not an Expression.
                // No need to walk — it's just an identifier or member access.
            }
            Expression::SequenceExpression(seq) => {
                for e in &seq.expressions {
                    self.walk_expression(e);
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for elem in &arr.elements {
                    match elem {
                        ArrayExpressionElement::SpreadElement(spread) => {
                            self.walk_expression(&spread.argument);
                        }
                        ArrayExpressionElement::Elision(_) => {}
                        _ => {
                            if let Some(expr) = elem.as_expression() {
                                self.walk_expression(expr);
                            }
                        }
                    }
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.walk_expression(&p.value);
                            if self.has_violation() {
                                return;
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            self.walk_expression(&spread.argument);
                            if self.has_violation() {
                                return;
                            }
                        }
                    }
                }
            }
            Expression::AwaitExpression(aw) => {
                self.walk_expression(&aw.argument);
            }
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.walk_expression(arg);
                }
            }
            Expression::TemplateLiteral(tl) => {
                for expr in &tl.expressions {
                    self.walk_expression(expr);
                    if self.has_violation() {
                        return;
                    }
                }
            }
            Expression::ParenthesizedExpression(paren) => {
                self.walk_expression(&paren.expression);
            }
            Expression::ClassExpression(class) => {
                self.walk_class_body(&class.body);
            }
            Expression::ChainExpression(chain) => match &chain.expression {
                ChainElement::CallExpression(call) => {
                    self.check_call_callee(&call.callee);
                    if self.has_violation() {
                        return;
                    }
                    self.walk_expression(&call.callee);
                    if self.has_violation() {
                        return;
                    }
                    for arg in &call.arguments {
                        if let Some(expr) = arg.as_expression() {
                            self.walk_expression(expr);
                            if self.has_violation() {
                                return;
                            }
                        }
                    }
                }
                ChainElement::StaticMemberExpression(member) => {
                    self.check_static_member(member);
                    if self.has_violation() {
                        return;
                    }
                    self.walk_expression(&member.object);
                }
                ChainElement::ComputedMemberExpression(member) => {
                    self.check_computed_member(member);
                    if self.has_violation() {
                        return;
                    }
                    self.walk_expression(&member.object);
                    if self.has_violation() {
                        return;
                    }
                    self.walk_expression(&member.expression);
                }
                ChainElement::PrivateFieldExpression(pf) => {
                    self.walk_expression(&pf.object);
                }
                _ => {}
            },
            // PrivateFieldExpression (from MemberExpression inheritance)
            Expression::PrivateFieldExpression(pf) => {
                self.walk_expression(&pf.object);
            }
            // Literals and other safe expressions — no walk needed
            _ => {}
        }
    }

    fn check_new_callee(&mut self, callee: &Expression<'_>) {
        match callee {
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();
                match name {
                    "Function" => self.report(
                        "new Function() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "AsyncFunction" => self.report(
                        "new AsyncFunction() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "GeneratorFunction" => self.report(
                        "new GeneratorFunction() constructor — dynamic code generation is banned in the sandbox",
                    ),
                    "Proxy" => self.report("new Proxy() is banned in the sandbox"),
                    _ => {}
                }
            }
            Expression::StaticMemberExpression(member) => {
                if let Expression::Identifier(obj) = &member.object {
                    if obj.name.as_str() == "WebAssembly" {
                        self.report("new WebAssembly.* is banned in the sandbox");
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Bypass detection tests (AST-01 to AST-13) ---

    #[test]
    fn ast_01_detects_direct_eval() {
        let code = r#"async () => { eval("1+1"); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect eval()");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AstViolation::BannedPattern { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn ast_02_detects_bracket_constructor_access() {
        let code = r#"async () => { ""["constructor"]["constructor"]("return this")(); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect [\"constructor\"] access");
    }

    #[test]
    fn ast_03_detects_tagged_template_string_raw() {
        let code = r#"async () => { String.raw`\x61\x62`; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect String.raw tagged template");
    }

    #[test]
    fn ast_04_detects_proxy_constructor() {
        let code = r#"async () => { new Proxy({}, { get: () => {} }); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Proxy constructor");
    }

    #[test]
    fn ast_05_detects_indirect_eval_via_constructor_chain() {
        let code = r#"async () => { "".constructor.constructor("return this")(); }"#;
        let result = validate_ast(code);
        assert!(
            result.is_err(),
            "should detect constructor.constructor chain"
        );
    }

    #[test]
    fn ast_06_detects_async_function_constructor() {
        let code = r#"async () => { AsyncFunction("return 1")(); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect AsyncFunction constructor");
    }

    #[test]
    fn ast_07_detects_generator_function_constructor() {
        let code = r#"async () => { GeneratorFunction("yield 1")(); }"#;
        let result = validate_ast(code);
        assert!(
            result.is_err(),
            "should detect GeneratorFunction constructor"
        );
    }

    #[test]
    fn ast_08_detects_reflect_construct() {
        let code = r#"async () => { Reflect.construct(Array, [1, 2, 3]); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Reflect.construct");
    }

    #[test]
    fn ast_09_detects_import_meta() {
        let code = r#"async () => { return import.meta.url; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect import.meta");
    }

    #[test]
    fn ast_10_detects_dynamic_import() {
        let code = r#"async () => { const m = await import("fs"); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect dynamic import()");
    }

    #[test]
    fn ast_11_detects_symbol_toprimitive() {
        let code = r#"async () => { obj[Symbol.toPrimitive] = () => "exploit"; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Symbol.toPrimitive");
    }

    #[test]
    fn ast_12_detects_symbol_hasinstance() {
        let code = r#"async () => { Object.defineProperty(obj, Symbol.hasInstance, { value: () => true }); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Symbol.hasInstance");
    }

    #[test]
    fn ast_13_detects_proto_access() {
        let code = r#"async () => { ({}).__proto__.polluted = true; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect __proto__ access");
    }

    // --- Safe pattern tests (AST-14 to AST-18) ---

    #[test]
    fn ast_14_allows_string_literal_containing_eval() {
        let code = r#"async () => { return "eval(x) is banned"; }"#;
        assert!(
            validate_ast(code).is_ok(),
            "string containing 'eval' should not be flagged"
        );
    }

    #[test]
    fn ast_15_allows_symbol_iterator() {
        let code = r#"async () => { for (const x of obj[Symbol.iterator]()) {} }"#;
        assert!(
            validate_ast(code).is_ok(),
            "Symbol.iterator should not be flagged"
        );
    }

    #[test]
    fn ast_16_allows_includes_constructor() {
        let code = r#"async () => { return name.includes("constructor"); }"#;
        assert!(
            validate_ast(code).is_ok(),
            "string 'constructor' in includes() should not be flagged"
        );
    }

    #[test]
    fn ast_17_allows_constructor_name_read() {
        let code = r#"async () => { return obj.constructor.name; }"#;
        assert!(
            validate_ast(code).is_ok(),
            "reading obj.constructor.name should not be flagged"
        );
    }

    #[test]
    fn ast_18_allows_legitimate_forge_code() {
        let code = r#"async () => {
            const result = await forge.callTool("server", "tool", { query: "test" });
            return result.data.filter(x => x.name.includes("constructor"));
        }"#;
        assert!(
            validate_ast(code).is_ok(),
            "legitimate forge code should pass"
        );
    }

    // --- Additional bypass detection (AST-19 to AST-26) ---

    #[test]
    fn ast_19_detects_function_constructor() {
        let code = r#"async () => { Function("return this")(); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Function() constructor");
    }

    #[test]
    fn ast_20_detects_new_function_constructor() {
        let code = r#"async () => { new Function("return process")(); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect new Function() constructor");
    }

    #[test]
    fn ast_21_detects_deno_access() {
        let code = r#"async () => { return Deno.readFile("/etc/passwd"); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect Deno.* access");
    }

    #[test]
    fn ast_22_detects_process_env() {
        let code = r#"async () => { return process.env.SECRET; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect process.env");
    }

    #[test]
    fn ast_23_detects_globalthis_bracket() {
        // Computed bracket access to globalThis is dangerous (dynamic name bypass)
        let code = r#"async () => { return globalThis["eval"]("1+1"); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect globalThis[...] access");
    }

    #[test]
    fn ast_allows_typeof_globalthis_prop() {
        // Static property reads like typeof globalThis.eval are just checks, not escapes
        let code = r#"async () => { return typeof globalThis.eval; }"#;
        assert!(
            validate_ast(code).is_ok(),
            "typeof globalThis.eval is a safe runtime check"
        );
    }

    #[test]
    fn ast_24_detects_string_from_char_code() {
        let code = r#"async () => { return String.fromCharCode(101, 118, 97, 108); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect String.fromCharCode() call");
    }

    #[test]
    fn ast_25_detects_deep_nesting() {
        let mut code = "async () => { ".to_string();
        for _ in 0..300 {
            code.push_str("if (true) { ");
        }
        code.push_str("return 1;");
        for _ in 0..300 {
            code.push('}');
        }
        code.push_str(" }");
        let result = validate_ast(&code);
        assert!(result.is_err(), "should detect excessive nesting");
        assert!(matches!(
            result.unwrap_err(),
            AstViolation::NestingTooDeep { .. }
        ));
    }

    #[test]
    fn ast_26_detects_with_statement() {
        // `with` is sloppy-mode only, but we still catch it if the parser accepts it
        let code = r#"async () => { with (obj) { return x; } }"#;
        // Note: oxc may parse this in module mode (strict), which makes `with` a parse error.
        // Either a parse error or a BannedPattern is acceptable.
        let result = validate_ast(code);
        assert!(result.is_err(), "with statement should be rejected");
    }

    // --- Additional safe patterns (AST-27, AST-28) ---

    #[test]
    fn ast_27_allows_data_process_status() {
        let code = r#"async () => { return data.process.status; }"#;
        assert!(
            validate_ast(code).is_ok(),
            "data.process.status should not be flagged"
        );
    }

    #[test]
    fn ast_28_allows_template_literal_with_banned_word_text() {
        let code = r#"async () => { return `eval is banned`; }"#;
        assert!(
            validate_ast(code).is_ok(),
            "template literal text containing 'eval' should not be flagged"
        );
    }

    // --- Nesting depth tests ---

    #[test]
    fn nesting_depth_normal_code_ok() {
        let code = "async () => { if (true) { for (let i = 0; i < 10; i++) { [1,2,3]; } } }";
        assert!(check_nesting_depth(code).is_ok());
    }

    #[test]
    fn nesting_depth_exactly_at_limit_ok() {
        let mut code = String::new();
        for _ in 0..MAX_NESTING_DEPTH {
            code.push('{');
        }
        for _ in 0..MAX_NESTING_DEPTH {
            code.push('}');
        }
        assert!(check_nesting_depth(&code).is_ok());
    }

    #[test]
    fn nesting_depth_over_limit_rejected() {
        let mut code = String::new();
        for _ in 0..MAX_NESTING_DEPTH + 1 {
            code.push('{');
        }
        for _ in 0..MAX_NESTING_DEPTH + 1 {
            code.push('}');
        }
        assert!(matches!(
            check_nesting_depth(&code),
            Err(AstViolation::NestingTooDeep { .. })
        ));
    }

    // --- WebAssembly detection ---

    #[test]
    fn ast_detects_webassembly_module() {
        let code = r#"async () => { new WebAssembly.Module(buf); }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect new WebAssembly.*");
    }

    #[test]
    fn ast_detects_webassembly_identifier() {
        let code = r#"async () => { const w = WebAssembly; }"#;
        let result = validate_ast(code);
        assert!(result.is_err(), "should detect WebAssembly reference");
    }
}
