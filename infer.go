package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"gopkg.in/yaml.v3"
)

type Path []string

func annotate(p Path, t *ast.Term) {
	t.Location = &ast.Location{}
	t.Location.Text, _ = json.Marshal(p)
	switch value := t.Value.(type) {
	case ast.Object:
		for _, key := range value.Keys() {
			if str, ok := key.Value.(ast.String); ok {
				p = append(p, string(str))
				annotate(p, value.Get(key))
				p = p[:len(p)-1]
			}
		}
	}
}

type trie map[string]trie

func (t trie) add(p Path) {
	if len(p) > 0 {
		if _, ok := t[p[0]]; !ok {
			t[p[0]] = map[string]trie{}
		}
		t[p[0]].add(p[1:])
	}
}

func (t trie) list() []Path {
    if len(t) == 0 {
        return []Path{{}}
    } else {
    	out := []Path{}
        for k, child := range t {
    		for _, childPath := range child.list() {
        		p := Path{k}
        		p = append(p, childPath...)
        		out = append(out, p)
    		}
        }
        return out
    }
}

func nodeToTerm(file string, node *yaml.Node) *ast.Term {
	var term *ast.Term
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			term = ast.StringTerm(node.Value)
		default:
			fmt.Fprintf(os.Stderr, "Unknown tag: %s\n", node.Tag)
			return nil
		}
	case yaml.DocumentNode:
		term = nodeToTerm(file, node.Content[0])
	case yaml.MappingNode:
		props := [][2]*ast.Term{}
		for i := 0; i < len(node.Content); i += 2 {
			k := nodeToTerm(file, node.Content[i])
			v := nodeToTerm(file, node.Content[i+1])
			props = append(props, [2]*ast.Term{k, v})
		}
		term = ast.ObjectTerm(props...)
	default:
		fmt.Fprintf(os.Stderr, "Unknown kind: %v\n", node.Kind)
		return nil
	}
	term.Location = &ast.Location{
		File: file,
		Row:  node.Line,
		Col:  node.Column,
	}
	return term
}

func location(file string, node *yaml.Node, path Path) *loc {
	if len(path) > 0 {
		switch node.Kind {
		case yaml.DocumentNode:
			return location(file, node.Content[0], path)
		case yaml.MappingNode:
			for i := 0; i < len(node.Content); i += 2 {
				if node.Content[i].Value == path[0] {
					return location(file, node.Content[i+1], path[1:])
				}
			}
		}
	}
	return &loc{
		File:   file,
		Line:   node.Line,
		Column: node.Column,
	}
}

type loc struct {
	File   string
	Line   int
	Column int
}

type locationTracer struct {
	locations map[loc]struct{}
	trie      trie
}

func newLocationTracer() *locationTracer {
	return &locationTracer{locations: map[loc]struct{}{}, trie: trie{}}
}

func (t *locationTracer) Enabled() bool {
	return true
}

func (t *locationTracer) Trace(event *topdown.Event) {
	switch event.Op {
	case topdown.UnifyOp:
		t.traceUnify(event)
	case topdown.EvalOp:
		t.traceEval(event)
	}
}

func (t *locationTracer) coverTerm(term *ast.Term) {
	if term.Location != nil && term.Location.Text != nil {
		t.locations[loc{
			File:   term.Location.File,
			Line:   term.Location.Row,
			Column: term.Location.Col,
		}] = struct{}{}

		var path Path
		json.Unmarshal(term.Location.Text, &path)
		t.trie.add(path)
	}
}

func (t *locationTracer) traceUnify(event *topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		operands := expr.Operands()
		if len(operands) == 2 {
			t.coverTerm(event.Plug(operands[0]))
			t.coverTerm(event.Plug(operands[1]))
		}
	}
}

func (t *locationTracer) traceEval(event *topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		switch terms := expr.Terms.(type) {
		case []*ast.Term:
			if len(terms) < 1 {
				break
			}
			operator := terms[0]
			if _, ok := ast.BuiltinMap[operator.String()]; ok {
				for _, term := range terms[1:] {
					t.coverTerm(event.Plug(term))
				}
			}
		case *ast.Term:
			t.coverTerm(event.Plug(terms))
		}
	}
}

func infer(file string) error {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	var node yaml.Node
	if err := yaml.Unmarshal(bytes, &node); err != nil {
		return err
	}
	input := nodeToTerm(file, &node)
	annotate(Path{}, input)
	fmt.Fprintf(os.Stderr, "Input: %v\n", input)

	if bytes, err = ioutil.ReadFile("policy.rego"); err != nil {
		return err
	}

	tracer := newLocationTracer()
	results, err := rego.New(
		rego.Module("policy.rego", string(bytes)),
		rego.ParsedInput(input.Value),
		rego.Query("data.policy.deny"),
		rego.Tracer(tracer),
	).Eval(context.Background())
	if err != nil {
		return err
	}

	locations := []*loc{}
	for _, path := range tracer.trie.list() {
    	locations = append(locations, location(file, &node, path))
	}

	fmt.Fprintf(os.Stderr, "Results: %v\n", results)
	fmt.Fprintf(os.Stderr, "Locations: %v\n", tracer.locations)
	fmt.Fprintf(os.Stderr, "Trie: %v\n", tracer.trie.list())
	fmt.Fprintf(os.Stderr, "Locations 2: %v\n", locations)
	return nil
}

func main() {
	if err := infer("template.yml"); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Hello world!\n")
}
