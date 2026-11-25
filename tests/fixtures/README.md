# Local TLS fixtures

`probe-ca-cert.pem` is a test-only root certificate. `probe-leaf-cert.pem` and its private key
are used by the local HTTPS fixture. The leaf private key is a disposable, public test credential
and must never be used outside tests. The test client trusts the root only when explicitly
supplied to the provider constructor; otherwise it uses the Node.js system certificate store.

`evidence-sample.html` contains passive metadata and asset references for Evidence Engine tests.
