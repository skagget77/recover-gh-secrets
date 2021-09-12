# Recover GitHub Secrets
A simple tool for recovering GitHub Actions Secrets from a GitHub repository.

The tool can be run in three different ways, each with an increased level of security. The least secure way, and the easiest, is to have the client output the Secrets directly to the log of the Action runner. Note that the Secrets are always encrypted with AES-256 but if the key ever leaks the Secrets would be compromised. One level up in security is to have the client send the Secrets to another machine instead of writing them to the log. The top level is to have the connection between the client and the remote machine protected by TLS with a custom CA certificate preventing the client from connecting to the wrong machine.

## How To Recover Secrets
This example

### 1. Pull Image
There are prebuild docker images for Linux/AMD64, Linux/ARM64v8 and Linux/ARM32v7. All images are hosted on GitHubs Container Registry and can be found [here](https://github.com/skagget77/recover-gh-secrets/pkgs/container/recover-gh-secrets).

Pull the lastest Linux/AMD64 image:
```
$ docker pull ghcr.io/skagget77/recover-gh-secrets:latest
latest: Pulling from skagget77/recover-gh-secrets
<...hash...>: Pull complete
<...hash...>: Pull complete
Digest: sha256:<...digest...>
Status: Downloaded newer image for ghcr.io/skagget77/recover-gh-secrets:latest
ghcr.io/skagget77/recover-gh-secrets:latest
```

### 2. Generate Key
The key is used to protect the Secrets outside of the repository. Because of this it's important that the key is kept secret.

Generate a new random key:
```
$ docker run --rm ghcr.io/skagget77/recover-gh-secrets genkey
rgMXauXNOI8Ta4ewmoPJhA61CvwV5zpQKaPaNJ6Rymw=
```

### 3. Run Server
The server can run either with or without TLS. The default port of the server is 19771.

Start the server with TLS:
```
$ docker run --rm --network=host ghcr.io/skagget77/recover-gh-secrets server -t
The server is listening on: 93.184.216.34:19771 172.17.0.1:19771
Running with TLS enabled. Set RECOVER_GH_SECRETS_CERT to the following CA
certificate on the client side:

-----BEGIN CERTIFICATE-----
MIIBsTCCAWOgAwIBAgIBATAFBgMrZXAwYDELMAkGA1UEBhMCU0UxEjAQBgNVBAcT
CVN0b2NraG9sbTEdMBsGA1UEChMUU2VjcmV0cyBSZWNvdmVyeSBJbmMxHjAcBgNV
BAMTFVJlY292ZXIgR0ggU2VjcmV0cyBDQTAeFw0yMTA5MTIxNjM4MDNaFw0yMTA5
MTQxNjM4MDNaMGAxCzAJBgNVBAYTAlNFMRIwEAYDVQQHEwlTdG9ja2hvbG0xHTAb
BgNVBAoTFFNlY3JldHMgUmVjb3ZlcnkgSW5jMR4wHAYDVQQDExVSZWNvdmVyIEdI
IFNlY3JldHMgQ0EwKjAFBgMrZXADIQDdxuFyC+EnlHlPP/yEsqkpgiXXMasWwqyi
+lxoCFkBI6NCMEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFPXi3kQbgCr64l/nxh+e9uvLOY7VMAUGAytlcANBAGT/D8fmZgBEuJ8L
rysYxJcpxEo9bpDQtEn/BbnEZTSLZNvM72y72gmOydWHHU+HExjQ1wgGu9DlEzEg
Z8hmbQU=
-----END CERTIFICATE-----

The certificate is valid for 24 hours. After that time you need to restart
the server to issue new certificates
```

Note that if you're running your server with TLS and it's behind a router with NAT you need to pass the IP address of the router to the `-t` flag. Otherwise the client will refuse to connect since the certificate does not contain the public IP address of the server.

### 4. Run Client
The client needs to run as a GitHub Action.

In the settings for the GitHub repository where the secrets you want to recover are, define a new repository secret named *RECOVER_GH_SECRETS_CERT*. The value should be the certificate written to the terminal by the server in step 3. Here it would be:
```
-----BEGIN CERTIFICATE-----
MIIBsTCCAWOgAwIBAgIBATAFBgMrZXAwYDELMAkGA1UEBhMCU0UxEjAQBgNVBAcT
CVN0b2NraG9sbTEdMBsGA1UEChMUU2VjcmV0cyBSZWNvdmVyeSBJbmMxHjAcBgNV
BAMTFVJlY292ZXIgR0ggU2VjcmV0cyBDQTAeFw0yMTA5MTIxNjM4MDNaFw0yMTA5
MTQxNjM4MDNaMGAxCzAJBgNVBAYTAlNFMRIwEAYDVQQHEwlTdG9ja2hvbG0xHTAb
BgNVBAoTFFNlY3JldHMgUmVjb3ZlcnkgSW5jMR4wHAYDVQQDExVSZWNvdmVyIEdI
IFNlY3JldHMgQ0EwKjAFBgMrZXADIQDdxuFyC+EnlHlPP/yEsqkpgiXXMasWwqyi
+lxoCFkBI6NCMEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFPXi3kQbgCr64l/nxh+e9uvLOY7VMAUGAytlcANBAGT/D8fmZgBEuJ8L
rysYxJcpxEo9bpDQtEn/BbnEZTSLZNvM72y72gmOydWHHU+HExjQ1wgGu9DlEzEg
Z8hmbQU=
-----END CERTIFICATE-----
```

Define another repository secret named *RECOVER_GH_SECRETS_REMOTE*. The value should be one of the IP addresses written to the terminal by the server in step 3. Here it would be:
```
93.184.216.34
```

Define yet another repository secret named *RECOVER_GH_SECRETS_KEY*. The value should be the key written to the terminal in step 2. Here it would be:
```
rgMXauXNOI8Ta4ewmoPJhA61CvwV5zpQKaPaNJ6Rymw=
```

Use the following workflow:
```
name: Recover Secrets
on: workflow_dispatch
jobs:
  recover:
    name: Recover Secrets
    runs-on: ubuntu-latest
    steps:
      - name: Recover Secrets
        uses: docker://ghcr.io/skagget77/recover-gh-secrets:latest
        with:
          args: client MY_SECRET
        env:
          RECOVER_GH_SECRETS_CERT: ${{ secrets.RECOVER_GH_SECRETS_CERT }}
          RECOVER_GH_SECRETS_KEY: ${{ secrets.RECOVER_GH_SECRETS_KEY }}
          RECOVER_GH_SECRETS_REMOTE: ${{ secrets.RECOVER_GH_SECRETS_REMOTE }}
          MY_SECRET: ${{ secrets.MY_SECRET }}
```

### 5. Decrypt
```
$ docker run --rm ghcr.io/skagget77/recover-gh-secrets:latest decrypt \
    rgMXauXNOI8Ta4ewmoPJhA61CvwV5zpQKaPaNJ6Rymw= \
    O7XIRGVIuCeflQe3H+0hm5wEFhdYm1fRHXlKznUSVR34CuZuHak1lwu6jTDqsrPGMeikMwsFfvc=
TEST_SECRET="My Supercerial Secret"
```
