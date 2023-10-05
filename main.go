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

type Location struct {
	File   string
	Line   int
	Column int
}

type Path []string

type Source struct {
	file string
	root *yaml.Node
}

func NewSource(file string) (*Source, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(bytes, &root); err != nil {
		return nil, err
	}

	return &Source{file: file, root: &root}, nil
}

func (s *Source) Location(path Path) *Location {
	cursor := s.root
	for len(path) > 0 {
		switch cursor.Kind {
		// Ignore multiple docs in our PoC
		case yaml.DocumentNode:
			cursor = cursor.Content[0]
		case yaml.MappingNode:
			for i := 0; i < len(cursor.Content); i += 2 {
				if cursor.Content[i].Value == path[0] {
					cursor = cursor.Content[i+1]
					path = path[1:]
				}
			}
		}
	}
	return &Location{
		File:   s.file,
		Line:   cursor.Line,
		Column: cursor.Column,
	}
}

type PathTree map[string]PathTree

func (t PathTree) Insert(path Path) {
	if len(path) > 0 {
		if _, ok := t[path[0]]; !ok {
			t[path[0]] = map[string]PathTree{}
		}
		t[path[0]].Insert(path[1:])
	}
}

func (t PathTree) List() []Path {
	if len(t) == 0 {
		return []Path{{}} // Return the empty path
	} else {
		out := []Path{}
		for k, child := range t {
			// Prepend `k` to every child path
			for _, childPath := range child.List() {
				path := Path{k}
				path = append(path, childPath...)
				out = append(out, path)
			}
		}
		return out
	}
}

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

type locationTracer struct {
	locations map[Location]struct{}
	tree      PathTree
}

func newLocationTracer() *locationTracer {
	return &locationTracer{locations: map[Location]struct{}{}, tree: PathTree{}}
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
		t.locations[Location{
			File:   term.Location.File,
			Line:   term.Location.Row,
			Column: term.Location.Col,
		}] = struct{}{}

		var path Path
		json.Unmarshal(term.Location.Text, &path)
		t.tree.Insert(path)
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
	source, err := NewSource(file)
	if err != nil {
		return err
	}

	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	var node yaml.Node
	if err := yaml.Unmarshal(bytes, &node); err != nil {
		return err
	}

	var doc interface{}
	if err := yaml.Unmarshal(bytes, &doc); err != nil {
		return err
	}

	input, err := ast.InterfaceToValue(doc)
	if err != nil {
		return err
	}

	annotate(Path{}, ast.NewTerm(input))
	fmt.Fprintf(os.Stderr, "Input: %v\n", input)

	if bytes, err = ioutil.ReadFile("policy.rego"); err != nil {
		return err
	}

	tracer := newLocationTracer()
	results, err := rego.New(
		rego.Module("policy.rego", string(bytes)),
		rego.ParsedInput(input),
		rego.Query("data.policy.deny"),
		rego.Tracer(tracer),
	).Eval(context.Background())
	if err != nil {
		return err
	}

	locations := []*Location{}
	for _, path := range tracer.tree.List() {
		locations = append(locations, source.Location(path))
	}

	fmt.Fprintf(os.Stderr, "Results: %v\n", results)
	fmt.Fprintf(os.Stderr, "Locations: %v\n", tracer.locations)
	fmt.Fprintf(os.Stderr, "Trie: %v\n", tracer.tree.List())
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
