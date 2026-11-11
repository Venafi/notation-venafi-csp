# v0.3.4

## Bug Fixes

* Built with Go 1.27.3, which rejects certificate chains from the compromised eMudhra intermediate CAs (v0.3.3 was built with Go 1.26.0)

## Others

* GitHub workflows take the Go version from go.mod
* Fixed two `go vet` errors (non-constant format strings) in the revocation checks


# v0.3.3

## Enhancements

* Code Sign Manager, SaaS support
* Support for verificationPlugin attribute opt-out


# v0.3.2

## Enhancements

* Deprecate revocation checks due to native support in notation 1.3.0


# v0.3.1

## Bug Fixes

* fix verificationPluginMinVersion for backwards compatibility of verification capabilities

# v0.3.0

## Enhancements

* Improved notation plugin management support
* COSE Envelope support
* Ratify support