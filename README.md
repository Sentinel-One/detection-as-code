# Detections as Code

Manage your SentinelOne detection rules the same way you manage code: in Git,
reviewed via Pull Requests, and deployed automatically by GitHub Actions.

This repo is a **reference implementation** — a starter template you can clone, drop your own rules into, point at
your SentinelOne console, and give an API token. It is provided as an example and is **not** actively maintained,
so expect to adapt the workflow to your own needs.

For more in-depth documentation and examples (multi-target deployments, advanced rule features, troubleshooting),
see the official SentinelOne documentation.

## How it works

- You write detection rules as YAML files under `detections/`.
- A `deployments.yaml` file says **where** to deploy them (which scope in your SentinelOne tenant)
and **what** to deploy (which files).
- A GitHub Actions workflow does the rest:
  - On a **Pull Request** → runs `diff` and posts a summary of what *would* change as a PR comment.
  - On **push to `main`** → runs `apply` and actually creates/updates/deletes the rules in SentinelOne console.

## Get started

### 1. Clone this repository

```bash
git clone https://github.com/sentinel-one/detections-as-code.git my-detections
cd my-detections
```

Then push it to your own GitHub repo (create an empty repo on GitHub first, then):

```bash
git remote set-url origin https://github.com/<your-org>/<your-repo>.git
git push -u origin main
```

### 2. Add your SentinelOne credentials to GitHub

In your repo on GitHub, go to **Settings → Secrets and variables → Actions** and add:

| Type     | Name            | Value                                                      |
|----------|-----------------|------------------------------------------------------------|
| Secret   | `DAC_API_TOKEN` | An API token from your SentinelOne console                 |
| Variable | `MGMT_URI`      | Your console URL, e.g. `https://usea1-xxx.sentinelone.net` |

#### How to get the `DAC_API_TOKEN`

In your SentinelOne management console:

1. Go to **Policies and settings → Console settings → User management → Service users** and click **New Service User**.
2. Give it a descriptive name (e.g. `detections-as-code`) and an expiration date.
3. Set its scope to one that covers **every** target scope you plan to deploy to (every `scopeId` / `scopeLevel`
listed under `targets:` in `deployments.yaml`).
4. Grant it a role with permission to manage **Custom Rules** and **Perform Advanced Actions** as well if you want
to hide rule logic.
5. Copy the generated API token — this is the only time it's shown — and paste it into the `DAC_API_TOKEN` GitHub secret.

> **Note:** Treat the token like a password. Rotate it on the expiration date and revoke it immediately
> if a runner or laptop is compromised. This example uses GitHub Actions secrets for simplicity. You may prefer a more
> secure secret store. Securing the token and controlling access to this
> detections repository is **your responsibility** — anyone who can read the token or push to `main` can change what
> runs in your SentinelOne console.

### 3. Point `deployments.yaml` at your scope

Edit `detections/deployments.yaml`:

```yaml
targets:
  dev:
    scopeId: "1234567890"   # must be a string
    scopeLevel: account     # one of: site, account, global

deploy:
  dev:
    - "shared/*.yaml"       # globs of rule files to deploy
```

Find your `scopeId` in the SentinelOne console or via the API.

### 4. Create, update, or delete a rule

Each YAML file under `detections/` (matched by a glob in `deployments.yaml`) is one detection rule.
What you do in Git determines what happens in SentinelOne management console:

- **Create** — add a new YAML file (or add a glob in `deployments.yaml` that matches a YAML file not previously deployed).
- **Update** — edit an existing YAML file.
- **Delete** — remove the YAML file (or remove its glob from `deployments.yaml`).

See `detections/shared/rule1.yaml` for an example rule.

> **Note:** The `id` field must be **unique within the repository**. It is the key used to match a YAML file to its
> rule in SentinelOne, so duplicates will fail validation and cause the action to fail.

### 5. Open a Pull Request

```bash
git checkout -b my-first-sync
git add detections/
git commit -m "My first sync"
git push -u origin my-first-sync
```

Open the PR on GitHub. The **Detections as Code** action will run automatically and post a comment showing exactly
what will change in your SentinelOne tenant — *no rules are modified yet*.

On a first run, no rules from this repo have been synced to your management console yet, so the diff should list one
**create** for every rule file matched by `deploy:` in `deployments.yaml` — and zero **updates** or **deletes**.

The same summary is also published as a **check-run** on the commit, visible in the PR's *Checks* tab and next to the
commit SHA.

### 6. Merge to deploy

Once the PR is approved and merged into `main`, the `apply` job runs and your rules go live in SentinelOne.
Check the **Actions** tab for the deployment summary, or the **check-run** posted on the merge commit.

The `apply` summary should match the `diff` summary you saw on the PR exactly — same number of creates, updates, and
deletes, and the same rule IDs in each list.

## Recommended GitHub repository settings

Because a merge to `main` deploys directly to your SentinelOne console, lock the branch down:

- **Branch protection on `main`** (Settings → Branches → Add rule):
  - Require a pull request before merging.
  - Require at least one approving review.
  - Require status checks to pass — select the **Detections as Code / diff** check.
  - Require branches to be up to date before merging.
- **Disable direct pushes** to `main` and disallow force-pushes and deletions.
- **Disable forking** (Settings → General → Features) so the `DAC_API_TOKEN` secret can't leak via a fork's workflows.
- **Limit who can manage Actions secrets/variables** — anyone with write access to `DAC_API_TOKEN` or `MGMT_URI` can redirect deployments.

