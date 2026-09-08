# Historical Windows evidence glossary

This file explains terms that may appear in old Windows records. It is not a current test plan or work queue. Current product behavior comes from the [product specification](../product-spec.md).

The old evidence system separated automated checks, operator observations, and unassisted beginner observations for one Windows installer. Labels such as `REHEARSAL`, `AUTO-OPERATOR`, `LIFECYCLE`, `BEGINNER`, and `SIGNING-VERIFY` describe those records only.

Its use of a single TCP connection to `127.0.0.1:9001` as a beginner result was a product mistake. That action proves only that one port accepted, refused, or timed out; it performs no security check. The feature may remain only as a plainly labeled connection utility outside the primary scan path.

Useful safety facts from the records remain valid:

- use only the target and activity the user explicitly authorized;
- do not stop or reconfigure an unrelated process that occupies a port;
- keep credentials out of chat, arguments, logs, and evidence;
- distinguish operator assistance from what a beginner completed;
- do not present source tests or process completion as scanner results;
- obtain fresh confirmation before destructive cleanup.

Old records state only what was observed at that time. New product work starts from the current beginner flow, upstream scanner behavior, and professional report.
