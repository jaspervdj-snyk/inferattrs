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

func (loc Location) String() string {
	return fmt.Sprintf("%s:%d:%d", loc.File, loc.Line, loc.Column)
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

func (source *Source) Location(path Path) *Location {
	cursor := source.root
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
		File:   source.file,
		Line:   cursor.Line,
		Column: cursor.Column,
	}
}

type PathTree map[string]PathTree

func (tree PathTree) Insert(path Path) {
	if len(path) > 0 {
		if _, ok := tree[path[0]]; !ok {
			tree[path[0]] = map[string]PathTree{}
		}
		tree[path[0]].Insert(path[1:])
	}
}

func (tree PathTree) List() []Path {
	if len(tree) == 0 {
		// Return the empty path
		return []Path{{}}
	} else {
		out := []Path{}
		for k, child := range tree {
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

func (tracer *locationTracer) Enabled() bool {
	return true
}

func (tracer *locationTracer) Trace(event *topdown.Event) {
	switch event.Op {
	case topdown.UnifyOp:
		tracer.traceUnify(event)
	case topdown.EvalOp:
		tracer.traceEval(event)
	}
}

func (tracer *locationTracer) traceUnify(event *topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		operands := expr.Operands()
		if len(operands) == 2 {
			tracer.used(event.Plug(operands[0]))
			tracer.used(event.Plug(operands[1]))
		}
	}
}

func (tracer *locationTracer) traceEval(event *topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		switch terms := expr.Terms.(type) {
		case []*ast.Term:
			if len(terms) < 1 {
				// I'm not sure what this is, but it's definitely
				// not a built-in function application.
				break
			}
			operator := terms[0]
			if _, ok := ast.BuiltinMap[operator.String()]; ok {
				for _, term := range terms[1:] {
					tracer.used(event.Plug(term))
				}
			}
		case *ast.Term:
			tracer.used(event.Plug(terms))
		}
	}
}

func annotate(path Path, term *ast.Term) {
	// Annotate current term by setting location.
	if bytes, err := json.Marshal(path); err == nil {
		term.Location = &ast.Location{}
		term.Location.File = "path:" + string(bytes)
	}
	// Recursively annotate children.
	switch value := term.Value.(type) {
	case ast.Object:
		for _, key := range value.Keys() {
			if str, ok := key.Value.(ast.String); ok {
				path = append(path, string(str))
				annotate(path, value.Get(key))
				path = path[:len(path)-1]
			}
		}
	}
}

func (tracer *locationTracer) used(term *ast.Term) {
	if term.Location != nil {
		if val := strings.TrimPrefix(term.Location.File, "path:"); val != term.Location.File {
			var path Path
			json.Unmarshal([]byte(val), &path)
			tracer.tree.Insert(path)
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
