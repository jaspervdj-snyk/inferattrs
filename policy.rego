package policy

deny[resourceId] {
	resource := input.Resources[resourceId]
	resource.Type == "AWS::EC2::Subnet"
	[_, mask] = split(resource.Properties.CidrBlock, "/")
	to_number(mask) < 24
}
