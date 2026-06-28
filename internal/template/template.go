// Package template provides a lightweight Jinja2-style template engine.
//
// It reuses gonja/v2's lexer and parser for full Jinja2 syntax support but
// implements its own evaluator that operates exclusively on map[string]any
// contexts via type assertions. This avoids reflect.MethodByName and
// reflect.FieldByName which defeat the Go linker's dead-code elimination and
// cause significant binary bloat (the linker must retain all methods on any
// type that could be passed to the template engine).
//
// Supported syntax:
//   - Variable interpolation: {{ var }}, {{ obj.attr }}, {{ list[0] }}
//   - Conditionals: {% if %} / {% elif %} / {% else %} / {% endif %}
//   - Loops: {% for item in list %} / {% else %} / {% endfor %}
//   - Operators: and, or, not, ==, !=, <, >, <=, >=, in, +, -, *, /
//   - Tests: is defined, is undefined, is none, is true, is false
//   - Function calls: {{ fn("arg1", "arg2") }}
package template

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/nikolalohinski/gonja/v2/config"
	"github.com/nikolalohinski/gonja/v2/nodes"
	"github.com/nikolalohinski/gonja/v2/parser"
	"github.com/nikolalohinski/gonja/v2/tokens"
)

// Func is the signature for custom template functions.
type Func func(args []any) (any, error)

// Template is a parsed template ready for execution. Parse a template once
// and execute it multiple times with different contexts.
type Template struct {
	root  *nodes.Template
	funcs map[string]Func
}

// Parse parses a Jinja2 template string. The returned Template can be
// executed against a map[string]any context. Returns an error if the
// template contains syntax errors or unsupported control structures.
func Parse(source string) (*Template, error) {
	cfg := config.New()
	stream := tokens.LexAll(source, cfg)
	p := parser.NewParser("", stream, cfg, nil, &controlStructures{})
	tpl, err := p.Parse()
	if err != nil {
		return nil, err
	}
	return &Template{root: tpl}, nil
}

// WithFunc registers a custom function that can be called from templates
// as {{ name("arg") }}. Returns the template for chaining.
func (t *Template) WithFunc(name string, fn Func) *Template {
	if t.funcs == nil {
		t.funcs = make(map[string]Func)
	}
	t.funcs[name] = fn
	return t
}

// Execute renders the template into w. Context values are looked up by key
// from ctx; nested map[string]any values support dotted access (e.g. obj.key).
func (t *Template) Execute(w io.Writer, ctx map[string]any) error {
	return renderNodes(w, t.root.Nodes, ctx, t.funcs)
}

// ExecuteToString is a convenience wrapper around Execute that returns the
// rendered output as a string.
func (t *Template) ExecuteToString(ctx map[string]any) (string, error) {
	var sb strings.Builder
	if err := t.Execute(&sb, ctx); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ReferencedVarNames returns names mentioned through the special var namespace
// anywhere in the template AST, including branches that are not taken at
// execution time. For example, both {{ var.foo }} and {{ var["foo"] }} mention
// "foo".
func (t *Template) ReferencedVarNames() map[string]struct{} {
	refs := make(map[string]struct{})
	collectVarRefsFromNodes(t.root.Nodes, refs)
	return refs
}

func collectVarRefsFromNodes(nodeList []nodes.Node, refs map[string]struct{}) {
	for _, node := range nodeList {
		switch n := node.(type) {
		case *nodes.Output:
			collectVarRefsFromExpr(n.Expression, refs)
			if n.Condition != nil {
				collectVarRefsFromExpr(n.Condition, refs)
			}
		case *nodes.ControlStructureBlock:
			collectVarRefsFromControl(n.ControlStructure, refs)
		}
	}
}

func collectVarRefsFromControl(cs nodes.ControlStructure, refs map[string]struct{}) {
	switch n := cs.(type) {
	case *ifNode:
		for _, cond := range n.conditions {
			collectVarRefsFromExpr(cond, refs)
		}
		for _, wrapper := range n.wrappers {
			collectVarRefsFromNodes(wrapper.Nodes, refs)
		}
		if n.elseWrapper != nil {
			collectVarRefsFromNodes(n.elseWrapper.Nodes, refs)
		}
	case *forNode:
		collectVarRefsFromExpr(n.iter, refs)
		if n.bodyWrapper != nil {
			collectVarRefsFromNodes(n.bodyWrapper.Nodes, refs)
		}
		if n.elseWrapper != nil {
			collectVarRefsFromNodes(n.elseWrapper.Nodes, refs)
		}
	case *setNode:
		collectVarRefsFromExpr(n.expr, refs)
	}
}

func collectVarRefsFromExpr(expr nodes.Expression, refs map[string]struct{}) {
	switch e := expr.(type) {
	case *nodes.Variable:
		collectVarRefsFromVariable(e, refs)
		for _, part := range e.Parts {
			for _, arg := range part.Args {
				collectVarRefsFromExpr(arg, refs)
			}
			for _, arg := range part.Kwargs {
				collectVarRefsFromExpr(arg, refs)
			}
		}
	case *nodes.GetAttribute:
		if isVarRoot(e.Node) {
			refs[e.Attribute] = struct{}{}
		}
		collectVarRefsFromNode(e.Node, refs)
	case *nodes.GetItem:
		if isVarRoot(e.Node) {
			if s, ok := stringLiteralFromNode(e.Arg); ok {
				refs[s] = struct{}{}
			}
		}
		collectVarRefsFromNode(e.Node, refs)
		collectVarRefsFromNode(e.Arg, refs)
	case *nodes.Call:
		collectVarRefsFromNode(e.Func, refs)
		for _, arg := range e.Args {
			collectVarRefsFromExpr(arg, refs)
		}
		for _, arg := range e.Kwargs {
			collectVarRefsFromExpr(arg, refs)
		}
	case *nodes.Negation:
		collectVarRefsFromExpr(e.Term, refs)
	case *nodes.BinaryExpression:
		collectVarRefsFromExpr(e.Left, refs)
		collectVarRefsFromExpr(e.Right, refs)
	case *nodes.UnaryExpression:
		collectVarRefsFromExpr(e.Term, refs)
	case *nodes.List:
		for _, item := range e.Val {
			collectVarRefsFromExpr(item, refs)
		}
	case *nodes.FilteredExpression:
		collectVarRefsFromExpr(e.Expression, refs)
		for _, filter := range e.Filters {
			for _, arg := range filter.Args {
				collectVarRefsFromExpr(arg, refs)
			}
			for _, arg := range filter.Kwargs {
				collectVarRefsFromExpr(arg, refs)
			}
		}
	case *nodes.TestExpression:
		collectVarRefsFromExpr(e.Expression, refs)
		for _, arg := range e.Test.Args {
			collectVarRefsFromExpr(arg, refs)
		}
		for _, arg := range e.Test.Kwargs {
			collectVarRefsFromExpr(arg, refs)
		}
	}
}

func collectVarRefsFromNode(n nodes.Node, refs map[string]struct{}) {
	if expr, ok := n.(nodes.Expression); ok {
		collectVarRefsFromExpr(expr, refs)
	}
}

func collectVarRefsFromVariable(v *nodes.Variable, refs map[string]struct{}) {
	if len(v.Parts) < 2 {
		return
	}
	if v.Parts[0].Type == nodes.VarTypeIdent && v.Parts[0].S == "var" && v.Parts[1].Type == nodes.VarTypeIdent {
		refs[v.Parts[1].S] = struct{}{}
	}
}

func isVarRoot(n nodes.Node) bool {
	switch v := n.(type) {
	case *nodes.Name:
		return v.Name.Val == "var"
	case *nodes.Variable:
		return len(v.Parts) == 1 && v.Parts[0].Type == nodes.VarTypeIdent && v.Parts[0].S == "var"
	}
	return false
}

func stringLiteralFromNode(n nodes.Node) (string, bool) {
	s, ok := n.(*nodes.String)
	if !ok {
		return "", false
	}
	return s.Val, true
}

func renderNodes(w io.Writer, nodeList []nodes.Node, ctx map[string]any, funcs map[string]Func) error {
	for _, node := range nodeList {
		if err := renderNode(w, node, ctx, funcs); err != nil {
			return err
		}
	}
	return nil
}

func renderNode(w io.Writer, node nodes.Node, ctx map[string]any, funcs map[string]Func) error {
	switch n := node.(type) {
	case *nodes.Data:
		_, err := io.WriteString(w, n.Data.Val)
		return err
	case *nodes.Output:
		val, err := eval(n.Expression, ctx, funcs)
		if err != nil {
			return err
		}
		if val == nil {
			return fmt.Errorf("undefined value in template expression")
		}
		_, err = fmt.Fprint(w, val)
		return err
	case *nodes.ControlStructureBlock:
		return renderControlStructure(w, n, ctx, funcs)
	case *nodes.Comment:
		return nil
	default:
		return fmt.Errorf("unsupported node type: %T", node)
	}
}

func renderControlStructure(w io.Writer, block *nodes.ControlStructureBlock, ctx map[string]any, funcs map[string]Func) error {
	switch cs := block.ControlStructure.(type) {
	case *ifNode:
		for i, cond := range cs.conditions {
			val, err := eval(cond, ctx, funcs)
			if err != nil {
				return err
			}
			if isTruthy(val) {
				return renderNodes(w, cs.wrappers[i].Nodes, ctx, funcs)
			}
		}
		if cs.elseWrapper != nil {
			return renderNodes(w, cs.elseWrapper.Nodes, ctx, funcs)
		}
		return nil
	case *forNode:
		return renderFor(w, cs, ctx, funcs)
	case *rawNode:
		_, err := io.WriteString(w, cs.data)
		return err
	case *setNode:
		val, err := eval(cs.expr, ctx, funcs)
		if err != nil {
			return err
		}
		ctx[cs.name] = val
		return nil
	default:
		return fmt.Errorf("unsupported control structure: %T", cs)
	}
}

func renderFor(w io.Writer, f *forNode, ctx map[string]any, funcs map[string]Func) error {
	obj, err := eval(f.iter, ctx, funcs)
	if err != nil {
		return err
	}
	items, ok := obj.([]any)
	if !ok {
		if obj == nil {
			items = nil
		} else {
			return fmt.Errorf("for loop requires a list, got %T", obj)
		}
	}
	if len(items) == 0 && f.elseWrapper != nil {
		return renderNodes(w, f.elseWrapper.Nodes, ctx, funcs)
	}
	for _, item := range items {
		inner := copyCtx(ctx)
		inner[f.key] = item
		if err := renderNodes(w, f.bodyWrapper.Nodes, inner, funcs); err != nil {
			return err
		}
	}
	return nil
}

// eval evaluates an expression node against the context.
func eval(expr nodes.Expression, ctx map[string]any, funcs map[string]Func) (any, error) {
	switch e := expr.(type) {
	case *nodes.String:
		return e.Val, nil
	case *nodes.Integer:
		return e.Val, nil
	case *nodes.Float:
		return e.Val, nil
	case *nodes.Bool:
		return e.Val, nil
	case *nodes.None:
		return nil, nil
	case *nodes.Name:
		return ctx[e.Name.Val], nil
	case *nodes.Variable:
		return resolveVariable(e, ctx, funcs)
	case *nodes.GetAttribute:
		return resolveGetAttribute(e, ctx, funcs)
	case *nodes.GetItem:
		return resolveGetItem(e, ctx, funcs)
	case *nodes.Call:
		return evalCall(e, ctx, funcs)
	case *nodes.Negation:
		val, err := eval(e.Term, ctx, funcs)
		if err != nil {
			return nil, err
		}
		return !isTruthy(val), nil
	case *nodes.BinaryExpression:
		return evalBinary(e, ctx, funcs)
	case *nodes.UnaryExpression:
		val, err := eval(e.Term, ctx, funcs)
		if err != nil {
			return nil, err
		}
		if e.Negative {
			switch v := val.(type) {
			case int:
				return -v, nil
			case float64:
				return -v, nil
			}
		}
		return val, nil
	case *nodes.List:
		var result []any
		for _, item := range e.Val {
			v, err := eval(item, ctx, funcs)
			if err != nil {
				return nil, err
			}
			result = append(result, v)
		}
		return result, nil
	case *nodes.FilteredExpression:
		if len(e.Filters) > 0 {
			return nil, fmt.Errorf("filters are not supported: %s", e.Filters[0].Name)
		}
		return eval(e.Expression, ctx, funcs)
	case *nodes.TestExpression:
		val, err := eval(e.Expression, ctx, funcs)
		if err != nil {
			return nil, err
		}
		return evalTest(e.Test, val, ctx, funcs)
	default:
		return nil, fmt.Errorf("unsupported expression type: %T", expr)
	}
}

func evalCall(c *nodes.Call, ctx map[string]any, funcs map[string]Func) (any, error) {
	// Resolve function name
	name, ok := c.Func.(*nodes.Name)
	if !ok {
		return nil, fmt.Errorf("cannot call non-name expression: %T", c.Func)
	}
	fn, ok := funcs[name.Name.Val]
	if !ok {
		return nil, fmt.Errorf("unknown function: %s", name.Name.Val)
	}
	args := make([]any, 0, len(c.Args))
	for _, arg := range c.Args {
		val, err := eval(arg, ctx, funcs)
		if err != nil {
			return nil, err
		}
		args = append(args, val)
	}
	return fn(args)
}

func resolveVariable(v *nodes.Variable, ctx map[string]any, funcs map[string]Func) (any, error) {
	if len(v.Parts) == 0 {
		return nil, nil
	}
	// Check if first part is a function call
	first := v.Parts[0]
	if first.IsFunctionCall && first.Type == nodes.VarTypeIdent {
		fn, ok := funcs[first.S]
		if !ok {
			return nil, fmt.Errorf("unknown function: %s", first.S)
		}
		args := make([]any, 0, len(first.Args))
		for _, arg := range first.Args {
			val, err := eval(arg, ctx, funcs)
			if err != nil {
				return nil, err
			}
			args = append(args, val)
		}
		return fn(args)
	}
	var current any = ctx
	for _, part := range v.Parts {
		switch part.Type {
		case nodes.VarTypeIdent:
			m, ok := current.(map[string]any)
			if !ok {
				return nil, nil
			}
			current = m[part.S]
		case nodes.VarTypeInt:
			slice, ok := current.([]any)
			if !ok {
				return nil, nil
			}
			if part.I < 0 || part.I >= len(slice) {
				return nil, nil
			}
			current = slice[part.I]
		}
	}
	return current, nil
}

func resolveGetAttribute(g *nodes.GetAttribute, ctx map[string]any, funcs map[string]Func) (any, error) {
	obj, err := evalNode(g.Node, ctx, funcs)
	if err != nil {
		return nil, err
	}
	m, ok := obj.(map[string]any)
	if !ok {
		return nil, nil
	}
	return m[g.Attribute], nil
}

func resolveGetItem(g *nodes.GetItem, ctx map[string]any, funcs map[string]Func) (any, error) {
	obj, err := evalNode(g.Node, ctx, funcs)
	if err != nil {
		return nil, err
	}
	key, err := evalNode(g.Arg, ctx, funcs)
	if err != nil {
		return nil, err
	}
	switch o := obj.(type) {
	case map[string]any:
		k, _ := key.(string)
		return o[k], nil
	case []any:
		idx, ok := key.(int)
		if !ok {
			return nil, nil
		}
		if idx < 0 || idx >= len(o) {
			return nil, nil
		}
		return o[idx], nil
	}
	return nil, nil
}

func evalNode(n nodes.Node, ctx map[string]any, funcs map[string]Func) (any, error) {
	if expr, ok := n.(nodes.Expression); ok {
		return eval(expr, ctx, funcs)
	}
	return nil, fmt.Errorf("cannot evaluate node type: %T", n)
}

func evalBinary(e *nodes.BinaryExpression, ctx map[string]any, funcs map[string]Func) (any, error) {
	left, err := eval(e.Left, ctx, funcs)
	if err != nil {
		return nil, err
	}
	op := e.Operator.Token.Val
	// Short-circuit for logical operators
	if op == "and" {
		if !isTruthy(left) {
			return left, nil
		}
		return eval(e.Right, ctx, funcs)
	}
	if op == "or" {
		if isTruthy(left) {
			return left, nil
		}
		return eval(e.Right, ctx, funcs)
	}
	right, err := eval(e.Right, ctx, funcs)
	if err != nil {
		return nil, err
	}
	switch op {
	case "==":
		return left == right, nil
	case "!=":
		return left != right, nil
	case "<", ">", "<=", ">=":
		return compareOrdered(left, right, op)
	case "+":
		return addValues(left, right)
	case "-":
		return subtractValues(left, right)
	case "*":
		return multiplyValues(left, right)
	case "/":
		return divideValues(left, right)
	case "in":
		return containsValue(right, left), nil
	default:
		return nil, fmt.Errorf("unsupported operator: %s", op)
	}
}

func evalTest(test *nodes.TestCall, val any, ctx map[string]any, funcs map[string]Func) (any, error) {
	switch test.Name {
	case "defined":
		return val != nil, nil
	case "undefined":
		return val == nil, nil
	case "none":
		return val == nil, nil
	case "true":
		return val == true, nil
	case "false":
		return val == false, nil
	case "in":
		if len(test.Args) == 0 {
			return false, nil
		}
		container, err := eval(test.Args[0], ctx, funcs)
		if err != nil {
			return nil, err
		}
		return containsValue(container, val), nil
	default:
		return nil, fmt.Errorf("unsupported test: %s", test.Name)
	}
}

func isTruthy(val any) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case float64:
		return v != 0
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

func toFloat(val any) (float64, bool) {
	switch v := val.(type) {
	case int:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

func compareOrdered(left, right any, op string) (any, error) {
	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if !lok || !rok {
		// string comparison
		ls, lok := left.(string)
		rs, rok := right.(string)
		if lok && rok {
			switch op {
			case "<":
				return ls < rs, nil
			case ">":
				return ls > rs, nil
			case "<=":
				return ls <= rs, nil
			case ">=":
				return ls >= rs, nil
			}
		}
		return false, nil
	}
	switch op {
	case "<":
		return lf < rf, nil
	case ">":
		return lf > rf, nil
	case "<=":
		return lf <= rf, nil
	case ">=":
		return lf >= rf, nil
	}
	return false, nil
}

func addValues(left, right any) (any, error) {
	if ls, ok := left.(string); ok {
		if rs, ok := right.(string); ok {
			return ls + rs, nil
		}
	}
	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if !lok || !rok {
		return nil, fmt.Errorf("cannot add %T and %T", left, right)
	}
	if isInt(left) && isInt(right) {
		return int(lf) + int(rf), nil
	}
	return lf + rf, nil
}

func subtractValues(left, right any) (any, error) {
	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if !lok || !rok {
		return nil, fmt.Errorf("cannot subtract %T and %T", left, right)
	}
	if isInt(left) && isInt(right) {
		return int(lf) - int(rf), nil
	}
	return lf - rf, nil
}

func multiplyValues(left, right any) (any, error) {
	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if !lok || !rok {
		return nil, fmt.Errorf("cannot multiply %T and %T", left, right)
	}
	if isInt(left) && isInt(right) {
		return int(lf) * int(rf), nil
	}
	return lf * rf, nil
}

func divideValues(left, right any) (any, error) {
	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if !lok || !rok {
		return nil, fmt.Errorf("cannot divide %T and %T", left, right)
	}
	if rf == 0 {
		return nil, fmt.Errorf("division by zero")
	}
	return lf / rf, nil
}

func isInt(val any) bool {
	_, ok := val.(int)
	return ok
}

func containsValue(container, item any) bool {
	switch c := container.(type) {
	case []any:
		if slices.Contains(c, item) {
			return true
		}
	case string:
		if s, ok := item.(string); ok {
			return strings.Contains(c, s)
		}
	case map[string]any:
		if k, ok := item.(string); ok {
			_, exists := c[k]
			return exists
		}
	}
	return false
}

func copyCtx(ctx map[string]any) map[string]any {
	out := make(map[string]any, len(ctx))
	maps.Copy(out, ctx)
	return out
}
