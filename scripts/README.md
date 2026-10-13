# Release Scripts

## Release Workflow

The repository is a single Go module (`github.com/lamassuiot/lamassuiot/v4`), so a release only needs one tag and no per-module version bumping.

1. **Prepare release commit** (manual):
   ```bash
   # Update CHANGELOG.md and RELEASE-NOTES.md
   git add CHANGELOG.md RELEASE-NOTES.md
   git commit -m "chore: release: prepare release 4.0.0"
   git push origin main
   ```

2. **Automated workflow** (triggered by push):
   - Extracts version from commit message
   - Creates the global tag (e.g., `v4.0.0`)
   - Creates the GitHub release and uploads the vendored dependencies
   - Builds and publishes Docker images
