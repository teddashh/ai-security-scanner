# Source availability and release blocker

ai-security-scanner does not redistribute a runnable CloudQuery engine image.
The CloudQuery CLI 6.41.1 image and source revision are independently pinned in
`plan.json`, but the required AWS source plugin cannot be installed anonymously:
the upstream registry responds with an authenticated-entitlement error.

The release disclosure supplied for the plugin is not a complete buildable
source and dependency closure. Publishing a scanner-owned binary or claiming a
runnable integration would therefore be misleading and would not establish a
reproducible MPL-2.0 redistribution path. CloudQuery remains explicitly
unavailable until a complete corresponding plugin source closure or an
anonymous, digest-verifiable upstream artifact exists.
