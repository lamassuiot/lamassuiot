# Release Scripts

## Version Bumping

### `bump-version.sh`

This script updates all internal module version references across the monorepo.

**Usage:**
```bash
./scripts/bump-version.sh <new-version>
```

**Example:**
```bash
./scripts/bump-version.sh 3.7.0
```

**What it does:**
1. Updates all `go.mod` files to reference the new version for internal dependencies
2. Runs `go mod tidy` on all modules to ensure consistency
3. Preserves the workspace setup (go.work continues to use local code)

**Modules updated:**
- core
- sdk
- shared/aws, shared/subsystems, shared/http
- engines/crypto/* (aws, filesystem, software, pkcs11, vaultkv2)
- engines/eventbus/* (amqp, aws)
- engines/storage/postgres
- engines/fs-storage/* (localfs, s3)
- backend
- connectors/awsiot
- monolithic

## Release Workflow

The complete release process works as follows:

1. **Prepare release commit** (manual):
   ```bash
   # Update CHANGELOG.md and RELEASE-NOTES.md
   git add CHANGELOG.md RELEASE-NOTES.md
   git commit -m "chore: release: prepare release 3.7.0"
   git push origin main
   ```

2. **Automated workflow** (triggered by push):
   - Extracts version from commit message
   - **Bumps all module versions** (NEW - fixes the version mismatch)
   - Creates global tag (e.g., `v3.7.0`)
   - Creates module-specific tags (e.g., `core/v3.7.0`, `backend/v3.7.0`)
   - Updates the `v3` branch
   - Builds and publishes Docker images

## Why Version Bumping is Important

When using Go workspaces:
- **Local development**: `go.work` ensures you use local source code
- **External consumers**: Download specific versions from GitHub tags

Without version bumping, you'd have:
- Tag says: `core/v3.7.0`
- But `core/go.mod` references: `sdk/v3.6.3` (wrong!)

This breaks external consumers who download the tagged version.

With version bumping:
- Tag says: `core/v3.7.0`
- And `core/go.mod` references: `sdk/v3.7.0` (correct!)

## Testing the Script Locally

```bash
# Create a test branch
git checkout -b test-version-bump

# Run the script
./scripts/bump-version.sh 3.7.0

# Review changes
git diff

# Verify it works
go work sync

# Clean up
git checkout main
git branch -D test-version-bump
```
