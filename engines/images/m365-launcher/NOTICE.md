# Managed Microsoft 365 launcher boundary

The launcher is project-owned code. It accepts only the immutable scope document and protected
credential file mounted by the desktop runtime. It never accepts a PowerShell expression, module
name, test path, product list, output filename, provider endpoint, or arbitrary engine argument.

The protected file must contain exactly one fresh `MSGRAPH_ACCESS_TOKEN` from a verified
provider-native or bootstrap-created read-only capability. The token remains in that file; it is
not copied into the child environment or command line. Each image starts one fixed script with
`pwsh -NoLogo -NoProfile -NonInteractive -File` after proving that the scope contains exactly one
Microsoft 365 tenant with `inventory_read` and `configuration_read` grants and no active scope.
