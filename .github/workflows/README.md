# GitHub Actions Docker Workflows

This directory contains GitHub Actions workflows for building and pushing Docker images for the 2026 eCTF project.

## Docker Workflows

### 1. **docker-build.yml** - Docker Build & Test
Automatically builds and tests the Docker image on every push and pull request.

**Triggers:**
- Push to `main` or `develop` branches (when firmware files change)
- Pull requests to `main` or `develop` branches
- Changes to the workflow file itself

**What it does:**
- Sets up Docker Buildx for efficient multi-platform builds
- Builds the Docker image from `./firmware/Dockerfile`
- Uses GitHub Actions cache to speed up subsequent builds
- Validates the image builds successfully

---

### 2. **docker-push.yml** - GitHub Container Registry Push
Automatically builds and pushes the Docker image to GitHub Container Registry (ghcr.io).

**Triggers:**
- Push to `main` branch (when firmware files change)
- Git tags matching `v*` pattern (e.g., `v1.0.0`)

**What it does:**
- Builds the Docker image
- Pushes to `ghcr.io/<owner>/2026-du-mitre-ectf/build-hsm`
- Tags images by branch name, semantic version, and commit SHA
- Uses automatic authentication with `GITHUB_TOKEN` (no setup needed)

**Image Tags:**
- `branch-main` - Built from main branch
- `v1.0.0` - Semantic version tags
- `sha-abc1234` - Commit SHA

---

### 3. **docker-hub-push.yml** - Docker Hub Push (Optional)
Manually push Docker images to Docker Hub if configured.

**Triggers:**
- Manual trigger via `workflow_dispatch` in Actions tab
- Git tags matching `release-v*` pattern

**Setup Required:**
Add these secrets to your GitHub repository (Settings → Secrets and Variables):
- `DOCKERHUB_USERNAME` - Your Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token (create at https://hub.docker.com/settings/security)

Without these secrets, this workflow will skip Docker Hub push.

---

## Python Workflows

### 4. **python-lint.yml** - Code Quality & Formatting
Validates Python code formatting and style using Black and linting tools.

**Triggers:**
- Push to `main` or `develop` branches (when Python files change)
- Pull requests to `main` or `develop` branches
- Changes to the workflow file itself

**What it does:**
- Checks code formatting with Black
- Runs Flake8 linter for style issues
- Runs Pylint for error checking
- Reports formatting and style violations

**Tools Used:**
- **Black** - Strict code formatter (PEP 8 compliant)
- **Flake8** - Style guide enforcement
- **Pylint** - Code analysis for errors and style

---

### 5. **python-tests.yml** - Testing & Coverage
Runs Python tests across multiple Python versions.

**Triggers:**
- Push to `main` or `develop` branches (when Python files change)
- Pull requests to `main` or `develop` branches
- Changes to the workflow file itself

**What it does:**
- Tests on Python 3.12 and 3.13
- Installs project dependencies from `pyproject.toml`
- Runs pytest with coverage reporting
- Uploads coverage to Codecov (optional)

**Prerequisites:**
- Tests should be in `ectf26_design/tests/` directory
- Named `test_*.py` or `*_test.py`

---

### 6. **python-secrets.yml** - Secrets Generation Validation
Validates the secrets generation command and can manually generate secrets.

**Triggers:**
- Push to `main` branch (validation only)
- Pull requests to `main` or `develop` branches (validation only)
- Manual trigger via `workflow_dispatch` to generate secrets

**What it does:**
- Validates the `gen_secrets.py` script is importable
- Tests secrets generation module
- Can manually invoke `uvx` command to generate secrets

**Manual Trigger Usage:**
1. Go to **Actions** tab
2. Select **Secrets Generation**
3. Click **Run workflow**
4. Enter space-separated group IDs (e.g., `1234 5678`)
5. Click **Run workflow**

---

## Usage

### View Workflow Status
Go to your repository → **Actions** tab to see:
- Workflow run history
- Build logs
- Status checks

### Manual Workflow Triggers
For workflows with `workflow_dispatch` trigger:
- Click the **Actions** tab
- Select the workflow name
- Click **Run workflow** 
- Fill in any required inputs
- Click **Run workflow**

### Docker Image Access

**From GitHub Container Registry:**
```bash
docker pull ghcr.io/<owner>/2026-du-mitre-ectf/build-hsm:main
docker pull ghcr.io/<owner>/2026-du-mitre-ectf/build-hsm:v1.0.0
```

Replace `<owner>` with your GitHub username or organization.

---

## Caching
All workflows use GitHub Actions cache to store Docker build layers and Python dependencies, significantly speeding up subsequent builds.

---

## Troubleshooting

**Workflow not triggering:**
- Ensure commit message refers to changed files in matching paths
- Check branch name matches trigger settings
- Workflows only run on changed files specified in `paths:`

**Python tests not running:**
- Ensure tests are in `ectf26_design/tests/` directory
- Use `test_*.py` or `*_test.py` naming convention
- Check `pyproject.toml` has correct dependencies

**Lint checks failing:**
- Run locally: `black ectf26_design/src/`
- Run locally: `flake8 ectf26_design/src/ --max-line-length=100`

**Docker push fails with authentication error:**
- Verify `GITHUB_TOKEN` has `packages: write` permission (default in public repos)
- For Docker Hub, verify `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are set correctly

**Image size too large:**
- Consider adding a `.dockerignore` file in `firmware/` directory
- Optimize Dockerfile RUN commands
