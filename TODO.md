# Fix .vsix Installation Issue — TODO

- [x] Analyze root cause (missing `node_modules` in .vsix due to `.vscodeignore`)
- [x] Edit `.vscodeignore` to remove `node_modules/**` exclusion
- [x] Verify `vsce` packaging now includes `minimatch` in `node_modules/`
- [x] Confirm plan completion

