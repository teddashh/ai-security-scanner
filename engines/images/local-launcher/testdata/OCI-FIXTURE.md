# OCI image-layout smoke fixture

`oci-layout/` is generated deterministically by
`scripts/generate-oci-layout-fixture.mjs`. Its one uncompressed tar layer
contains `app/lib/spring-core-2.5.6.SEC03.jar`, a 1,105-byte fixture copied from
the checksum-pinned Trivy source revision
`e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994` at
`pkg/dependency/parser/java/jar/testdata/test.jar` (SHA-256
`b9883ae1fd6b53762b285cfeb1e59bb52313855893fd3cd1ff1eafea26faa41e`).

The JAR makes the OCI boundary test meaningful: Trivy must finish without a
Java-index lookup or network because its managed OCI-image profile explicitly
scans only OS packages, while Grype must retain its offline language-package
cataloging path.

`../trivy-java-db-test.jar.base64` is a separate 277,275-byte JAR fixture from
the same checksum-pinned, Apache-2.0 Trivy source revision at
`pkg/fanal/analyzer/language/java/jar/testdata/test.jar` (SHA-256
`a5c71902c4d26153f1256491362dc94e6598e70e3ba06f19ee02b1dfcd392470`).
It intentionally lacks usable package metadata. Trivy's upstream Java-index
lookup resolves its SHA-1 to
`org.apache.tomcat.embed:tomcat-embed-websocket` 9.0.65, so the managed smoke
test proves that an unidentified JAR reaches the pinned Java DB and then the
ordinary vulnerability database while the scanner container has no network.
