package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

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
	term.Location = &location.Location{
		File: file,
		Row:  node.Line,
		Col:  node.Column,
	}
	return term
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
	fmt.Fprintf(os.Stderr, "Input: %v\n", input)

	if bytes, err = ioutil.ReadFile("policy.rego"); err != nil {
		return err
	}

	results, err := rego.New(
		rego.Module("policy.rego", string(bytes)),
		rego.ParsedInput(input.Value),
		rego.Query("data.policy.deny"),
	).Eval(context.Background())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Results: %v\n", results)
	return nil
}

func main() {
	if err := infer("template.yml"); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Hello world!\n")
}
