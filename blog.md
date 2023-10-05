---
title: 'Automagic source locations in Rego'
author: 'Jasper Van der Jeugt'
...

At Snyk, we are big fans of [Open Policy Agent]'s Rego.
Our [IaC product] is built around a large set of rules written in Rego,
and customers can add their [own custom rules] as well.

We recently released a [whole series of improvements] to our IaC product, and
in this blogpost we're taking a technical dive into a particularly interesting
feature: automagic source code locations for rule violations.

[Open Policy Agent]: https://www.openpolicyagent.org/
[IaC product]: https://snyk.io/product/infrastructure-as-code-security/
[own custom rules]: https://docs.snyk.io/scan-infrastructure/build-your-own-custom-rules/build-your-own-iac+-to-cloud-custom-rules
[whole series of improvements]: https://snyk.io/blog/announcing-iac-plus-early-access/

Let's start by looking at some example Rego code.  We'll be brief since this
is not the focus of this blogpost: if you want to learn Rego, we recommend
the excellent [OPA by Example] course.

[OPA by Example]: https://academy.styra.com/courses/opa-by-example

```rego
package rules.subnet_24

resource_type := "aws_subnet"

deny[info] {
	[_, mask] = split(input.cidr_block, "/")
	to_number(mask) < 24
	info := {"message": "Subnets should not use CIDR blocks larger than /24"}
}
```

Rego is a general-purpose language, and frameworks that use Rego typically have
some conventions on top of that to tailor it to their use case.  You can see
some of those in action here:

1.  `package rules.subnet_24`: we expect all IaC rules to live somewhere within
    the `rules` namespace.
2.  `resource_type := "aws_subnet"`: we're declaring a rule which will validate
    `aws_subnet` resources.  The engine itself will take care of gathering those
    resources, be it from terraform plan files, HCL files, or even resources
    found in cloud environments.
3.  `deny[info]`: the entrypoint to our rules is called `deny`; and `info` can
    be used by the rule author to present relevant information to the user.
    In this example we just set a message.

Let's look at some IaC code to make things a bit more concrete.  In this simple
file, we have one VPC and two subnets; out of which one subnet would be
considered invalid by our rule:

```hcl
resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.0.0/24"
}

resource "aws_subnet" "backup" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.128.0/20"
}
```

So far so good; and with some HCL parsing we can easily imagine tying this
together

1.  Example with manual attributes
2.  Inferring attributes with tracer
3.  Policy engine output?
