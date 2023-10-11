package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

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

func (l Location) String() string {
	return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column)
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

type locationTracer struct {
	tree PathTree
}

func newLocationTracer() *locationTracer {
	return &locationTracer{tree: PathTree{}}
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

func (t *locationTracer) traceUnify(event *topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		operands := expr.Operands()
		if len(operands) == 2 {
			t.used(event.Plug(operands[0]))
			t.used(event.Plug(operands[1]))
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
					t.used(event.Plug(term))
				}
			}
		case *ast.Term:
			t.used(event.Plug(terms))
		}
	}
}

func annotate(p Path, t *ast.Term) {
	if bytes, err := json.Marshal(p); err == nil {
		t.Location = &ast.Location{}
		t.Location.File = "path:" + string(bytes)
	}
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

func (t *locationTracer) used(term *ast.Term) {
	if term.Location != nil {
		if val := strings.TrimPrefix(term.Location.File, "path:"); val != term.Location.File {
			var path Path
			json.Unmarshal([]byte(val), &path)
			t.tree.Insert(path)
		}
	}
}

func infer(policy string, file string) error {
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
	if bytes, err = ioutil.ReadFile(policy); err != nil {
		return err
	}

	tracer := newLocationTracer()
	results, err := rego.New(
		rego.Module(policy, string(bytes)),
		rego.ParsedInput(input),
		rego.Query("data.policy.deny"),
		rego.Tracer(tracer),
	).Eval(context.Background())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Results: %v\n", results)
	for _, path := range tracer.tree.List() {
		fmt.Fprintf(os.Stderr, "Location: %s\n", source.Location(path).String())
	}
	return nil
}

func main() {
	if err := infer("policy.rego", "template.yml"); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
