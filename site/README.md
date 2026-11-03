# nimbus website + docs

`make site` builds the landing page and docs into `site/public/` (plain static files, MkDocs with the custom cwm theme in `site/theme/`). `make site-serve` previews with live reload. Pages that come from repo files (`docs/checks.md`, `cloud-posture.example.yaml`) are pulled in by `site/hooks.py` at build time.

Deploy `site/public/` anywhere:

- **GitHub Pages:** build with `make site` in an Actions workflow and publish `site/public` (`actions/upload-pages-artifact` + `actions/deploy-pages`), or push it to a `gh-pages` branch (`ghp-import -n -p site/public`).
- **Cloudflare Pages / Netlify:** build command `make site`, output directory `site/public`.
- **Any static host (nginx, OpenBSD httpd, S3):** copy `site/public/` to the web root.
- **Custom domain:** set `site_url` in `site/mkdocs.yml` to `https://<your-domain>/`, and for GitHub Pages add `site/docs/CNAME` containing just the domain (it's copied into the build). Example: `# echo docs.example.com > site/docs/CNAME`.
- `site/docs/assets/dashboard.png` is the screenshot on the landing page; until it exists, a placeholder box shows instead.
