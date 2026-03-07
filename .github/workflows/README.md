# GitHub Actions Docker Workflows

This directory contains GitHub Actions workflows for building and pushing Docker images for the 2026 eCTF project.

## Workflows

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

## Usage

### View Workflow Status
Go to your repository → **Actions** tab to see:
- Workflow run history
- Build logs
- Status checks

### Manual Workflow Triggers
- Click the **Actions** tab
- Select **Docker Hub Push (Optional)**
- Click **Run workflow** and select options

### Docker Image Access

**From GitHub Container Registry:**
```bash
docker pull ghcr.io/<owner>/2026-du-mitre-ectf/build-hsm:main
docker pull ghcr.io/<owner>/2026-du-mitre-ectf/build-hsm:v1.0.0
```

Replace `<owner>` with your GitHub username or organization.

---

## Caching
All workflows use GitHub Actions cache to store Docker build layers, significantly speeding up subsequent builds.

---

## Troubleshooting

**Workflow not triggering:**
- Ensure commit message refers to changed files in `firmware/` or `.github/workflows/`
- Check branch name matches trigger settings

**Push fails with authentication error:**
- Verify `GITHUB_TOKEN` has `packages: write` permission (default in public repos)
- For Docker Hub, verify `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are set correctly

**Image size too large:**
- Consider adding a `.dockerignore` file in `firmware/` directory
- Optimize Dockerfile RUN commands
