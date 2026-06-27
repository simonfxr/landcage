package template

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
