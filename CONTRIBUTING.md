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