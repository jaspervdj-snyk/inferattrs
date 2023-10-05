---
title: 'Automagic source locations in Rego'
author: 'Jasper Van der Jeugt'
...

# Introduction

At Snyk, we are big fans of [Open Policy Agent]'s Rego.
Our [IaC product] is built around a large set of rules written in Rego,
and customers can add their [own custom rules] as well.

~~~{.go snippet="main.go"}
type locationTracer
~~~

We recently released a [whole series of improvements] to our IaC product, and
in this blogpost we're taking a technical dive into a particularly interesting
feature: automagic source code locations for rule violations.

[Open Policy Agent]: https://www.openpolicyagent.org/
[IaC product]: https://snyk.io/product/infrastructure-as-code-security/
[own custom rules]: https://docs.snyk.io/scan-infrastructure/build-your-own-custom-rules/build-your-own-iac+-to-cloud-custom-rules
[whole series of improvements]: https://snyk.io/blog/announcing-iac-plus-early-access/

The code in this blogpost serves as a standalone example of this technique,
but in order to lean more towards a short story than an epic, we'll need to
make some simplifications.  The full implementation of this is available
in our [unified policy engine].

[unified policy engine]: https://github.com/snyk/policy-engine/

Let's start by looking at CloudFormation example.  While our IaC engine supports
many formats, with a strong focus around Terraform, CloudFormation is a good
subject for this blogpost since we can parse it without too many dependencies
(it's just YAML after all).

~~~{.yaml include="template.yml"}
~~~

We want to ensure no subnets use a CIDR block larger than `/24`.  We can write
a Rego policy to do just that.

~~~{.ruby include="policy.rego"}
~~~

This way, `deny` will produce a set of _denied_ resources.  We won't go into how
Rego works in detail since that's not the goal of this blogpost: if you want to
learn Rego, we recommend the excellent [OPA by Example] course.

[OPA by Example]: https://academy.styra.com/courses/opa-by-example

We can subdivide the problem in two parts:

1.  We'll want to infer that our policy uses the `CidrBlock` attribute
2.  Then, we'll retrieve the source code location for this

Let's start with (2) since it provides a good way to familiarize ourselves with
the code.

# Source Location retrieval

A source location looks like this:

~~~{.go snippet="main.go"}
type Location
~~~

We will also introduce an auxiliary type to represent paths in YAML.  Note that
we won't support arrays in our proof-of-concept, so we can get by just using an
array of strings.

~~~{.go snippet="main.go"}
type Path
~~~

One example of a path would be something like:

~~~{.go}
Path{"Resources", "BackupSubnet", "Properties", "CidrBlock"}
~~~

Now we can provide a convenience type to load YAML and tell us the `Location`
of certain `Path`s.

~~~{.go snippet="main.go"}
type Source
~~~

~~~{.go snippet="main.go"}
func NewSource
~~~

Finding the source location of a `Path` comes down to walking a tree of YAML
nodes:

~~~{.go snippet="main.go"}
func (s *Source) Location
~~~

# Sets and trees of paths

With that out of the way, we've reduced the problem from automatically
inferring _source locations_ that are used in a policy to automatically
inferring _attribute paths_.

This is also significant for other reasons -- e.g., Snyk can apply the same
policies to IaC resources as well as resources discovered through cloud scans,
the latter of which don't really have meaningful source locations, but they do
have meaningful attribute paths!

Next, we want to define sets of attribute paths.  Since paths are backed by
arrays, we unfortunately can't use something like `map[Path]struct{}` as a set
in Go.

Instead, we will need to store these in a recursive tree.

~~~{.go snippet="main.go"}
type PathTree
~~~

This representation has other advantages: in general, we only care about the
_longest_ paths that a policy uses, since they are more _specific_.
Our example policy is using
`Path{"Resources", "BackupSubnet", "Properties"}` as well as
`Path{"Resources", "BackupSubnet", "Properties", "CidrBlock"}`, and we only
care about the latter.

We'll define a recursive method to insert a `Path` into our tree:

~~~{.go snippet="main.go"}
func (t PathTree) Insert
~~~

As well as a way to get a list of `Path`s back out.  This does a bit of
unnecessary allocation, but we can live with that.

~~~{.go snippet="main.go"}
func (t PathTree) List
~~~
