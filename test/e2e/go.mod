module github.com/cvdtang/openstack-tpm/test/e2e

go 1.27.3

require (
	github.com/cvdtang/openstack-tpm v0.0.0
	github.com/google/go-tpm v0.9.8
	github.com/spiffe/spire-api-sdk v1.16.0
	google.golang.org/grpc v1.85.0
)

require (
	github.com/caarlos0/env/v11 v11.4.2 // indirect
	github.com/gophercloud/gophercloud/v2 v2.15.0 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/cvdtang/openstack-tpm => ../..
