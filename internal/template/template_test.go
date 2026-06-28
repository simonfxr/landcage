package template

import "strings"

import "testing"

func TestReferencedVarNamesIncludesBranchesAndLoopBodies(t *testing.T) {
	tpl, err := Parse(`{% if false %}{{ var.branch }}{% else %}{% for x in items %}{{ var.loop }}{% endfor %}{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	for _, name := range []string{"branch", "loop"} {
		if _, ok := refs[name]; !ok {
			t.Fatalf("missing ref %q in %#v", name, refs)
		}
	}
}

func TestReferencedVarNamesIncludesBracketSyntax(t *testing.T) {
	tpl, err := Parse(`{{ var["profile"] }} {{ env["HOME"] }}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["profile"]; !ok {
		t.Fatalf("missing bracket ref in %#v", refs)
	}
	if _, ok := refs["HOME"]; ok {
		t.Fatalf("env ref should not be reported as template var: %#v", refs)
	}
}

func TestReferencedVarNamesIncludesExpressionOperands(t *testing.T) {
	tpl, err := Parse(`{% if var.enabled and "x" in [var.item] %}yes{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	for _, name := range []string{"enabled", "item"} {
		if _, ok := refs[name]; !ok {
			t.Fatalf("missing ref %q in %#v", name, refs)
		}
	}
}

func TestReferencedVarNamesIncludesSetExpression(t *testing.T) {
	tpl, err := Parse(`{% set x = var.profile %}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["profile"]; !ok {
		t.Fatalf("missing ref 'profile' in %#v", refs)
	}
}

func TestReferencedVarNamesExemptsIsDefinedTest(t *testing.T) {
	tpl, err := Parse(`{% if var.opt is defined %}{{ var.opt }}{% else %}default{% endif %}{{ var.required }}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["opt"]; ok {
		t.Fatalf("var tested with 'is defined' should be exempt: %#v", refs)
	}
	if _, ok := refs["required"]; !ok {
		t.Fatalf("missing required ref in %#v", refs)
	}
}

func TestReferencedVarNamesExemptsIsUndefinedTest(t *testing.T) {
	tpl, err := Parse(`{% if var.missing is undefined %}fallback{% else %}{{ var.missing }}{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["missing"]; ok {
		t.Fatalf("var tested with 'is undefined' should be exempt: %#v", refs)
	}
}

func TestReferencedVarNamesExemptOverridesUnconditionalUse(t *testing.T) {
	// If var.foo appears in both an "is defined" test and unconditionally,
	// the exemption wins. Render will still fail at runtime if not provided.
	tpl, err := Parse(`{% if var.foo is defined %}guarded{% endif %}{{ var.foo }}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["foo"]; ok {
		t.Fatalf("expected foo to be exempt (current behavior): %#v", refs)
	}
}

func TestReferencedVarNamesExemptNegatedDefined(t *testing.T) {
	tpl, err := Parse(`{% if not (var.foo is defined) %}fallback{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	refs := tpl.ReferencedVarNames()
	if _, ok := refs["foo"]; ok {
		t.Fatalf("negated is-defined should still exempt: %#v", refs)
	}
}

func TestRenderRawBlock(t *testing.T) {
	tpl, err := Parse(`before {% raw %}{{ var.not_rendered }}{% endraw %} after`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{
		"var": map[string]any{"not_rendered": "wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != `before {{ var.not_rendered }} after` {
		t.Fatalf("got %q", got)
	}
}

func TestRenderIfElifWithoutElseDoesNotRenderFallback(t *testing.T) {
	tpl, err := Parse(`{% if false %}A{% elif false %}B{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderArithmeticAndComparisons(t *testing.T) {
	tpl, err := Parse(`{% if (a + 2) >= 4 and b * 2 == 6 %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"a": 2, "b": 3})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
}

func TestParseMalformedTemplateFails(t *testing.T) {
	if _, err := Parse(`{% if %}missing condition{% endif %}`); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestOutputNilErrorsStrictMode(t *testing.T) {
	tpl, err := Parse(`{{ missing }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{})
	if err == nil {
		t.Fatal("expected error for nil output")
	}
}

func TestOutputOrOperatorBypassesNilError(t *testing.T) {
	tpl, err := Parse(`{{ missing or "default" }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "default" {
		t.Fatalf("got %q", got)
	}
}

func TestSetAssignsVariable(t *testing.T) {
	tpl, err := Parse(`{% set x = "hello" %}{{ x }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestSetWithExpression(t *testing.T) {
	tpl, err := Parse(`{% set path = base + "/sub" %}{{ path }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"base": "/home"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/sub" {
		t.Fatalf("got %q", got)
	}
}

func TestSetInsideForDoesNotPropagateToOuterScope(t *testing.T) {
	// set inside a for loop should NOT modify the outer scope
	tpl, err := Parse(`{% set x = "outer" %}{% for i in items %}{% set x = "inner" %}{% endfor %}{{ x }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"items": []any{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "outer" {
		t.Fatalf("set inside for leaked to outer scope: got %q, want %q", got, "outer")
	}
}

func TestSetOverwritesInOuterScope(t *testing.T) {
	tpl, err := Parse(`{% set x = "first" %}{% set x = "second" %}{{ x }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("got %q", got)
	}
}

func TestForBasicIteration(t *testing.T) {
	tpl, err := Parse(`{% for x in items %}[{{ x }}]{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"items": []any{"a", "b", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "[a][b][c]" {
		t.Fatalf("got %q", got)
	}
}

func TestForElseOnEmptyList(t *testing.T) {
	tpl, err := Parse(`{% for x in items %}{{ x }}{% else %}empty{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"items": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "empty" {
		t.Fatalf("got %q", got)
	}
}

func TestForElseOnNilList(t *testing.T) {
	tpl, err := Parse(`{% for x in items %}{{ x }}{% else %}empty{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "empty" {
		t.Fatalf("got %q", got)
	}
}

func TestForOnNonListErrors(t *testing.T) {
	tpl, err := Parse(`{% for x in items %}{{ x }}{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{"items": "not a list"})
	if err == nil {
		t.Fatal("expected error for non-list iteration")
	}
}

func TestForIntegerIteration(t *testing.T) {
	tpl, err := Parse(`{% for x in items %}{{ x }}{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"items": []any{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "123" {
		t.Fatalf("got %q", got)
	}
}

func TestIfTruthiness(t *testing.T) {
	tests := []struct {
		name string
		ctx  map[string]any
		want string
	}{
		{"nil is falsy", map[string]any{}, "no"},
		{"false is falsy", map[string]any{"v": false}, "no"},
		{"true is truthy", map[string]any{"v": true}, "yes"},
		{"empty string is falsy", map[string]any{"v": ""}, "no"},
		{"non-empty string is truthy", map[string]any{"v": "x"}, "yes"},
		{"zero int is falsy", map[string]any{"v": 0}, "no"},
		{"non-zero int is truthy", map[string]any{"v": 42}, "yes"},
		{"empty list is falsy", map[string]any{"v": []any{}}, "no"},
		{"non-empty list is truthy", map[string]any{"v": []any{1}}, "yes"},
		{"empty map is falsy", map[string]any{"v": map[string]any{}}, "no"},
		{"non-empty map is truthy", map[string]any{"v": map[string]any{"k": 1}}, "yes"},
	}
	tpl, err := Parse(`{% if v %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tpl.ExecuteToString(tt.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIfUndefinedVarDoesNotError(t *testing.T) {
	// {% if undefined_var %} should NOT error, just be falsy
	tpl, err := Parse(`{% if undefined_var %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatalf("if with undefined var should not error: %v", err)
	}
	if got != "no" {
		t.Fatalf("got %q, want %q", got, "no")
	}
}

func TestOutputUndefinedVarErrors(t *testing.T) {
	// {{ undefined_var }} MUST error (strict nil on output)
	tpl, err := Parse(`{{ undefined_var }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{})
	if err == nil {
		t.Fatal("expected error for undefined var in output")
	}
}

func TestOutputNestedUndefinedErrors(t *testing.T) {
	// {{ obj.missing }} where obj exists but missing key → nil → error
	tpl, err := Parse(`{{ obj.missing }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{"obj": map[string]any{}})
	if err == nil {
		t.Fatal("expected error for nil nested attr in output")
	}
}

func TestIfElifElse(t *testing.T) {
	tpl, err := Parse(`{% if x == 1 %}one{% elif x == 2 %}two{% elif x == 3 %}three{% else %}other{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		x    int
		want string
	}{
		{1, "one"},
		{2, "two"},
		{3, "three"},
		{99, "other"},
	}
	for _, tt := range tests {
		got, err := tpl.ExecuteToString(map[string]any{"x": tt.x})
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("x=%d: got %q, want %q", tt.x, got, tt.want)
		}
	}
}

func TestOperatorNot(t *testing.T) {
	tpl, err := Parse(`{% if not flag %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"flag": false})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
}

func TestOperatorIn(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
		ctx  map[string]any
		want string
	}{
		{"string in list", `{% if "b" in items %}yes{% else %}no{% endif %}`, map[string]any{"items": []any{"a", "b", "c"}}, "yes"},
		{"string not in list", `{% if "z" in items %}yes{% else %}no{% endif %}`, map[string]any{"items": []any{"a", "b"}}, "no"},
		{"substring in string", `{% if "lo" in word %}yes{% else %}no{% endif %}`, map[string]any{"word": "hello"}, "yes"},
		{"key in map", `{% if "k" in m %}yes{% else %}no{% endif %}`, map[string]any{"m": map[string]any{"k": 1}}, "yes"},
		{"key not in map", `{% if "z" in m %}yes{% else %}no{% endif %}`, map[string]any{"m": map[string]any{"k": 1}}, "no"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl, err := Parse(tt.tmpl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tpl.ExecuteToString(tt.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOperatorStringComparison(t *testing.T) {
	tpl, err := Parse(`{% if a < b %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"a": "apple", "b": "banana"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
}

func TestArithmeticOperators(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
		ctx  map[string]any
		want string
	}{
		{"addition int", `{{ a + b }}`, map[string]any{"a": 3, "b": 4}, "7"},
		{"subtraction", `{{ a - b }}`, map[string]any{"a": 10, "b": 3}, "7"},
		{"multiplication", `{{ a * b }}`, map[string]any{"a": 3, "b": 4}, "12"},
		{"division float", `{{ a / b }}`, map[string]any{"a": 10, "b": 4}, "2.5"},
		{"string concat", `{{ a + b }}`, map[string]any{"a": "hello", "b": " world"}, "hello world"},
		{"negative unary", `{{ -a }}`, map[string]any{"a": 5}, "-5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl, err := Parse(tt.tmpl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tpl.ExecuteToString(tt.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDivisionByZeroErrors(t *testing.T) {
	tpl, err := Parse(`{{ a / b }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{"a": 10, "b": 0})
	if err == nil {
		t.Fatal("expected division by zero error")
	}
}

func TestTestIsDefined(t *testing.T) {
	tpl, err := Parse(`{% if x is defined %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"x": "val"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
	got, err = tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "no" {
		t.Fatalf("got %q", got)
	}
}

func TestTestIsUndefined(t *testing.T) {
	tpl, err := Parse(`{% if x is undefined %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
}

func TestTestIsNone(t *testing.T) {
	tpl, err := Parse(`{% if x is none %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"x": nil})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
	got, err = tpl.ExecuteToString(map[string]any{"x": "val"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "no" {
		t.Fatalf("got %q", got)
	}
}

func TestTestIsTrueIsFalse(t *testing.T) {
	tpl, err := Parse(`{% if x is true %}T{% elif x is false %}F{% else %}O{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		val  any
		want string
	}{
		{true, "T"},
		{false, "F"},
		{"truthy string", "O"},
		{0, "O"},
	}
	for _, tt := range tests {
		got, err := tpl.ExecuteToString(map[string]any{"x": tt.val})
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("val=%v: got %q, want %q", tt.val, got, tt.want)
		}
	}
}

func TestFunctionCall(t *testing.T) {
	tpl, err := Parse(`{{ myfunc("hello") }}`)
	if err != nil {
		t.Fatal(err)
	}
	tpl.WithFunc("myfunc", func(args []any) (any, error) {
		return "got:" + args[0].(string), nil
	})
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "got:hello" {
		t.Fatalf("got %q", got)
	}
}

func TestFunctionCallMultipleArgs(t *testing.T) {
	tpl, err := Parse(`{{ concat("a", "b", "c") }}`)
	if err != nil {
		t.Fatal(err)
	}
	tpl.WithFunc("concat", func(args []any) (any, error) {
		var s strings.Builder
		for _, a := range args {
			s.WriteString(a.(string))
		}
		return s.String(), nil
	})
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestFunctionCallUnknownErrors(t *testing.T) {
	tpl, err := Parse(`{{ unknown_fn() }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown function")
	}
}

func TestFunctionCallInCondition(t *testing.T) {
	tpl, err := Parse(`{% if check(x) %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	tpl.WithFunc("check", func(args []any) (any, error) {
		return args[0].(int) > 5, nil
	})
	got, err := tpl.ExecuteToString(map[string]any{"x": 10})
	if err != nil {
		t.Fatal(err)
	}
	if got != "yes" {
		t.Fatalf("got %q", got)
	}
}

func TestFilterUnsupportedErrors(t *testing.T) {
	tpl, err := Parse(`{{ x|upper }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.ExecuteToString(map[string]any{"x": "hi"})
	if err == nil {
		t.Fatal("expected error for unsupported filter")
	}
}

func TestListLiteral(t *testing.T) {
	tpl, err := Parse(`{% for x in ["a", "b"] %}{{ x }}{% endfor %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestGetItemBracketAccess(t *testing.T) {
	tpl, err := Parse(`{{ m["key"] }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"m": map[string]any{"key": "val"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "val" {
		t.Fatalf("got %q", got)
	}
}

func TestGetItemListIndex(t *testing.T) {
	tpl, err := Parse(`{{ items[1] }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"items": []any{"a", "b", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "b" {
		t.Fatalf("got %q", got)
	}
}

func TestCommentIgnored(t *testing.T) {
	tpl, err := Parse(`before{# this is a comment #}after`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "beforeafter" {
		t.Fatalf("got %q", got)
	}
}

func TestAndOrShortCircuit(t *testing.T) {
	// "or" short-circuits: if left is truthy, right is not evaluated
	tpl, err := Parse(`{{ x or "default" }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.ExecuteToString(map[string]any{"x": "present"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "present" {
		t.Fatalf("got %q", got)
	}

	// "and" short-circuits: if left is falsy, returns left
	tpl2, err := Parse(`{% if x and y %}yes{% else %}no{% endif %}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tpl2.ExecuteToString(map[string]any{"x": "", "y": "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "no" {
		t.Fatalf("got %q", got)
	}
}

func TestEqualityAndInequality(t *testing.T) {
	tests := []struct {
		tmpl string
		ctx  map[string]any
		want string
	}{
		{`{% if x == "a" %}y{% else %}n{% endif %}`, map[string]any{"x": "a"}, "y"},
		{`{% if x != "a" %}y{% else %}n{% endif %}`, map[string]any{"x": "b"}, "y"},
		{`{% if x == 1 %}y{% else %}n{% endif %}`, map[string]any{"x": 1}, "y"},
		{`{% if x != 1 %}y{% else %}n{% endif %}`, map[string]any{"x": 2}, "y"},
	}
	for _, tt := range tests {
		tpl, err := Parse(tt.tmpl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tpl.ExecuteToString(tt.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("%s: got %q, want %q", tt.tmpl, got, tt.want)
		}
	}
}
