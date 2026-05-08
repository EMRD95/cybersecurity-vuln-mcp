# Contributing Guidelines

Thank you for your interest in contributing to the **Cybersecurity Vulnerability Intelligence MCP** project.

## Branching Strategy (GitFlow)

This repository follows a strict **GitFlow-like** branching model:

- **`main`** — Production-ready code. Direct pushes are **prohibited**. All changes must arrive via Pull Request from `development` or release branches.
- **`development`** — Integration branch for active features. Pull requests from feature branches land here.
- **`feature/*`** — Short-lived branches for individual features or bugfixes. Branch from `development`.
- **`release/*`** — Preparation for a production release. Branch from `development`, merge into `main`.
- **`hotfix/*`** — Critical production patches. Branch from `main`, merge into both `main` and `development`.

### Workflow Summary

1. Fork the repository (for external contributors) or clone for internal access.
2. Checkout `development` and pull latest changes.
3. Create a feature branch: `git checkout -b feature/your-feature-name`.
4. Work, commit, and push your branch.
5. Open a **Pull Request** into `development`.
6. Ensure CI checks pass and at least one code review approval is obtained.
7. Squash-merge is preferred for feature branches.

## Commit Message Convention

- Use present tense: "Add CWE bulk lookup tool"
- Keep the subject line under 72 characters
- Reference issues/PRs when applicable: `Fixes #42`

## CI / Quality Gates

All pull requests must pass:

- TypeScript compilation (`npm run build`)
- Type checking (`npx tsc --noEmit`)
- Docker image build verification
- Shell script syntax check (`bash -n cve_mapper.sh`)

## Security

- Do **not** commit API keys, tokens, or private environment files.
- Use `.env.example` as a template and keep secrets in your local `.env` or vault.
- Report vulnerabilities privately via GitHub Security advisories before public disclosure.