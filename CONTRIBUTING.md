# Getting Started

## Prerequisites

Before contributing to LamassuIot, make sure you have the following tools installed:

1. **Docker**: LamassuIot uses containers to simplify development and execution.  
   - Follow the official instructions to install Docker on your system:  
     [Install Docker](https://docs.docker.com/engine/install)

2. **Go**: The project is written in Go, so you need a properly configured Go development environment.  
   - Download and install the latest version of Go from:  
     [Install Go](https://go.dev/doc/install)

   ### PKCS#11 / CGO (C compiler) requirement

   LamassuIoT includes a PKCS#11 crypto engine that depends on native C libraries. Building or running parts of the project that use the PKCS#11 engine requires CGO to be enabled so the Go toolchain can link with C code.

   To enable CGO when building or testing, set the `CGO_ENABLED` environment variable to `1` and ensure a C compiler and build tools are installed on your system. Example commands:

   ```sh
   # enable CGO for a single command
   CGO_ENABLED=1 go build ./...

   # enable CGO for running tests
   CGO_ENABLED=1 go test ./...

   # or export it for the current shell session
   export CGO_ENABLED=1
   ```

   Install a C compiler / build tools (examples):

   - Ubuntu / Debian:

   ```sh
   sudo apt update
   sudo apt install -y build-essential
   ```

   - Fedora:

   ```sh
   sudo dnf install -y gcc make pkgconfig
   ```

   - CentOS / RHEL:

   ```sh
   sudo yum groupinstall -y "Development Tools"
   ```

   - Arch Linux:

   ```sh
   sudo pacman -S --needed base-devel
   ```

   - macOS (Xcode command line tools):

   ```sh
   xcode-select --install
   ```

   Notes:

   - CGO complicates cross-compilation. If you need to build for a different target architecture, prefer building on the target platform or use a container image that includes the required C toolchain.
   - If you build Docker images for the project that require PKCS#11 support, ensure the image includes a C compiler and the necessary headers (for example by using a `build-essential`-equipped base image during the build stage or installing packages inside the Dockerfile).

   ## Go build tags used in this repository

   This repository uses Go build tags to optionally include or exclude features at compile time. Below is a list of the common build tags found in the codebase and what they control:

   - `noaws` — when present (build with `-tags noaws`), AWS-related components (AWS Connector, S3 fs-storage registration, etc.) are excluded. Default build includes AWS components.
   - `noamqp` — when present, AMQP/RabbitMQ eventbus registration is excluded.
   - `novault` — when present, Vault crypto engine registration is excluded.
   - `nopkcs11` — when present, PKCS#11 crypto engine registration is excluded.
   - `nojs` — when present, the JavaScript-based alert/event filter registrar is excluded.
   - `windows` / `!windows` — platform-specific files use the `windows` tag to include Windows-only implementations (for example PKCS#11 has a Windows stub). Most PKCS#11 code is excluded on Windows builds.

   Examples:

   ```sh
   # Build excluding PKCS#11 and AWS components
   go build -tags "nopkcs11 noaws" ./...

   # Build with no extra tags (default includes components guarded by !no* build tags)
   go build ./...
   ```

   Notes on build tags:

   - Files that use `//go:build !noaws` are compiled unless you explicitly pass the `noaws` tag.
   - The `-tags` flag accepts a space-separated list of tags. Use quotes to prevent shell splitting when needed.
   - Some files use platform build tags like `windows` or `!windows` — these are handled automatically by the Go toolchain based on the target OS.


## Cloning and Setup

To set up the project locally, follow these steps:

1. **Clone the repository**  
   Use the following command to clone the LamassuIot repository:  

   ``` sh
   git clone https://github.com/lamassuiot/lamassuiot.git
   ```

2. **Verifying the Setup**  
    To ensure that everything is set up correctly, run the development entry point:

    ``` sh
   cd lamassuiot
   go run monolithic/cmd/development/main.go
   ```
    If the setup is correct, you should see the application running without errors.

    https://localhost:8443/

    Once these steps are completed, you are ready to proceed with building and running the project.

# Semantic Commit Messages

See how a minor change to your commit message style can make you a better programmer.

Format: `<type>: <service>: <subject>`

## Example

```
feat: AWS Connector: add hat wobble
^--^  ^-----------^  ^------------^
|     |              |
|     |              +-> Summary in present tense.
|     |      
|     +-> Service being updated: CA, Device Manager, DMS Manager, AWS Connector, Alerts
|
+-------> Type: chore, feat, fix, bump, remove, security or test
```

More Examples:

- `chore`: (updating grunt tasks etc; no production code change)
- `feat`: (new feature for the user, not a new feature for build script)
- `fix`: (bug fix for the user, not a fix to a build script)
- `bump`: (bump libraries or go version number)
- `remove`: (deleted feature)
- `security`: (security fix)
- `test`: (adding missing tests, refactoring tests; no production code change)

References:

- https://www.conventionalcommits.org/
- https://seesparkbox.com/foundry/semantic_commit_messages
- http://karma-runner.github.io/1.0/dev/git-commit-msg.html

## Signed Commits

All commits must be signed with the `-s` flag. This flag adds a "Signed-off-by" line at the end of the commit message, indicating that the contributor agrees to the Developer Certificate of Origin (DCO).

To sign a commit, use the following command:

```sh
git commit -s -m "your commit message"
```

The `-s` flag ensures that your commit message includes a line that looks like this:

```
Signed-off-by: Your Name <your.email@example.com>
```

This line certifies that you wrote the code or otherwise have the right to submit it under the open source license indicated in the repository.