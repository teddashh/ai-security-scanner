# OCI image-layout smoke fixture

`oci-layout/` is generated deterministically by
`scripts/generate-oci-layout-fixture.mjs`. Its one uncompressed tar layer
contains `app/lib/spring-core-2.5.6.SEC03.jar`, a 1,105-byte fixture copied from
the checksum-pinned Trivy source revision
`e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994` at
`pkg/dependency/parser/java/jar/testdata/test.jar` (SHA-256
`b9883ae1fd6b53762b285cfeb1e59bb52313855893fd3cd1ff1eafea26faa41e`).

The JAR makes the boundary test meaningful: Trivy must finish without a Java
database or network because the managed profile explicitly scans only OS
packages, while Grype must retain its offline language-package cataloging path.
