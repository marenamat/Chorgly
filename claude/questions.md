# Questions / Action items for guardian

## GitHub Pages not enabled (pipeline run 24584609081)

The `Deploy GitHub Pages` workflow on `main` fails at the **Setup Pages** step
(`actions/configure-pages@v5`). This means GitHub Pages has not been enabled for
`marenamat/chorgly` yet.

**Action needed:** Go to the repository Settings → Pages, set the source to
`GitHub Actions`, and re-run the workflow. The `docs/` directory is ready to deploy.

… *Done. Set to actions*
