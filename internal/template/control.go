package template

import (
	"github.com/nikolalohinski/gonja/v2/nodes"
	"github.com/nikolalohinski/gonja/v2/parser"
	"github.com/nikolalohinski/gonja/v2/tokens"
)

// controlStructures implements parser.ControlStructureGetter with only the
// control structures we support. This avoids importing gonja's exec package
// (which contains reflect.MethodByName) and its builtin control structures.
type controlStructures struct{}

func (cs *controlStructures) Get(name string) (parser.ControlStructureParser, bool) {
	switch name {
	case "if":
		return parseIf, true
	case "for":
		return parseFor, true
	case "set":
		return parseSet, true
	case "raw":
		return parseRaw, true
	default:
		return nil, false
	}
}

// ifNode represents a parsed {% if %} block. It holds the parsed condition
// expressions and body wrappers but contains no evaluation logic itself —
// that lives in the evaluator (renderControlStructure).
type ifNode struct {
	location    *tokens.Token
	conditions  []nodes.Expression
	wrappers    []*nodes.Wrapper
	elseWrapper *nodes.Wrapper
}

func (n *ifNode) Position() *tokens.Token { return n.location }
func (n *ifNode) String() string          { return "if" }

func parseIf(p *parser.Parser, args *parser.Parser) (nodes.ControlStructure, error) {
	n := &ifNode{location: args.Current()}

	cond, err := args.ParseExpression()
	if err != nil {
		return nil, err
	}
	n.conditions = append(n.conditions, cond)

	if !args.End() {
		return nil, args.Error("if-condition is malformed", nil)
	}

	for {
		wrapper, tagArgs, err := p.WrapUntil("elif", "else", "endif")
		if err != nil {
			return nil, err
		}
		n.wrappers = append(n.wrappers, wrapper)

		if wrapper.EndTag == "elif" {
			cond, err = tagArgs.ParseExpression()
			if err != nil {
				return nil, err
			}
			n.conditions = append(n.conditions, cond)
			if !tagArgs.End() {
				return nil, tagArgs.Error("elif-condition is malformed", nil)
			}
		} else {
			if !tagArgs.End() {
				return nil, tagArgs.Error("arguments not allowed here", nil)
			}
		}

		if wrapper.EndTag == "else" {
			wrapper, tagArgs, err = p.WrapUntil("endif")
			if err != nil {
				return nil, err
			}
			if !tagArgs.End() {
				return nil, tagArgs.Error("arguments not allowed here", nil)
			}
			n.elseWrapper = wrapper
			break
		}

		if wrapper.EndTag == "endif" {
			break
		}
	}
	return n, nil
}

// forNode represents a parsed {% for key in expr %} block.
type forNode struct {
	location    *tokens.Token
	key         string
	iter        nodes.Expression
	bodyWrapper *nodes.Wrapper
	elseWrapper *nodes.Wrapper
}

func (n *forNode) Position() *tokens.Token { return n.location }
func (n *forNode) String() string          { return "for" }

func parseFor(p *parser.Parser, args *parser.Parser) (nodes.ControlStructure, error) {
	n := &forNode{location: args.Current()}

	keyToken := args.Match(tokens.Name)
	if keyToken == nil {
		return nil, args.Error("expected identifier in for-loop", nil)
	}
	n.key = keyToken.Val

	if args.Match(tokens.In) == nil {
		return nil, args.Error("expected 'in' keyword", nil)
	}

	iter, err := args.ParseExpression()
	if err != nil {
		return nil, err
	}
	n.iter = iter

	if !args.End() {
		return nil, args.Error("malformed for-loop args", nil)
	}

	wrapper, endargs, err := p.WrapUntil("else", "endfor")
	if err != nil {
		return nil, err
	}
	n.bodyWrapper = wrapper

	if !endargs.End() {
		return nil, endargs.Error("arguments not allowed here", nil)
	}

	if wrapper.EndTag == "else" {
		wrapper, endargs, err = p.WrapUntil("endfor")
		if err != nil {
			return nil, err
		}
		n.elseWrapper = wrapper
		if !endargs.End() {
			return nil, endargs.Error("arguments not allowed here", nil)
		}
	}

	return n, nil
}

// rawNode represents a {% raw %} block whose content is output verbatim
// without any template processing.
type rawNode struct {
	location *tokens.Token
	data     string
}

func (n *rawNode) Position() *tokens.Token { return n.location }
func (n *rawNode) String() string          { return "raw" }

func parseRaw(p *parser.Parser, args *parser.Parser) (nodes.ControlStructure, error) {
	if !args.End() {
		return nil, args.Error("arguments not allowed here", nil)
	}
	wrapper, _, err := p.WrapUntil("endraw")
	if err != nil {
		return nil, err
	}
	n := &rawNode{location: args.Current()}
	for _, node := range wrapper.Nodes {
		data, ok := node.(*nodes.Data)
		if !ok {
			return nil, p.Error("raw block must contain only text", node.Position())
		}
		n.data += data.Data.Val
	}
	return n, nil
}

// setNode represents a {% set name = expr %} assignment.
type setNode struct {
	location *tokens.Token
	name     string
	expr     nodes.Expression
}

func (n *setNode) Position() *tokens.Token { return n.location }
func (n *setNode) String() string          { return "set" }

func parseSet(p *parser.Parser, args *parser.Parser) (nodes.ControlStructure, error) {
	n := &setNode{location: args.Current()}

	nameToken := args.Match(tokens.Name)
	if nameToken == nil {
		return nil, args.Error("expected variable name after 'set'", nil)
	}
	n.name = nameToken.Val

	if args.Match(tokens.Assign) == nil {
		return nil, args.Error("expected '=' after variable name", nil)
	}

	expr, err := args.ParseExpression()
	if err != nil {
		return nil, err
	}
	n.expr = expr

	if !args.End() {
		return nil, args.Error("unexpected tokens after set expression", nil)
	}
	return n, nil
}
