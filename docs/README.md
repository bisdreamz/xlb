# XLB documentation site

The public documentation for XLB is built from `docs/` with MkDocs Material and published at
[docs.runxlb.com](https://docs.runxlb.com).

## Prerequisites

Install the documentation tooling once:

```bash
pipx install mkdocs
pipx inject mkdocs mkdocs-material
npm install
```

The generated `site/` directory and `node_modules/` are intentionally ignored by Git.

## Work locally

```bash
npm run dev
```

Build with MkDocs strict mode before committing:

```bash
npm run verify
```

The XLB repository also exposes `cargo run --package xtask -- gendocs`, which regenerates the
configuration reference from the Rust configuration types before running the same strict build.

## Deploy to Cloudflare Pages

Authenticate Wrangler, then deploy a preview or production build:

```bash
npm run deploy:preview
npm run deploy:production
```

Both commands rebuild the site before uploading `site/`. Production is the `main` branch of the
`run-xlb-docs` Pages project, which serves `docs.runxlb.com`.
