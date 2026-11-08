# Detection as Code

Manage your SentinelOne detection rules the same way you manage code: in Git,
reviewed via Pull Requests, and deployed automatically by GitHub Actions.

This repo is a **reference implementation** provided for illustrative purposes only. 
It is a starter template you can adapt to your environment, and is not a production-ready deployment architecture or a substitute for your own security review, access controls, and credential management decisions. 
It is provided as an example and is not actively maintained.

For more in-depth documentation and examples (multi-target deployments, advanced rule features, troubleshooting),
see the official SentinelOne documentation.

## How it works

- You write detection rules as YAML files under `detections/`.
- A `consoles/<name>.yaml` file per SentinelOne console says **where** to deploy them (which scope in that console)
and **what** to deploy (which files).
- A GitHub Actions workflow does the rest, once per console file:
  - On a **Pull Request** → runs `diff` and posts a summary of what *would* change as a PR comment.
  - On **push to `main`** → runs `apply` and actually creates/updates/removes the rules in SentinelOne console.

## Get started

### 1. Clone this repository

```bash
git clone https://github.com/sentinel-one/detection-as-code.git my-detections
cd my-detections
```

Then push it to your own GitHub repo (create an empty repo on GitHub first, then):

```bash
git remote set-url origin https://github.com/<your-org>/<your-repo>.git
git push -u origin main
```

### 2. Add your SentinelOne credentials to GitHub

In your repo on GitHub, go to **Settings → Secrets and variables → Actions** and add one secret per console:

| Type     | Name                | Value                                      |
|----------|---------------------|--------------------------------------------|
| Secret   | `DAC_API_TOKEN_DEV` | An API token from your SentinelOne console |

The secret name is up to you; the console file's `tokenSecret` (step 3) must match it.

#### How to get the API token

In your SentinelOne management console:

1. Go to **Policies and settings → Console settings → User management → Service users** and click **New Service User**.
2. Give it a descriptive name (e.g. `detection-as-code`) and an expiration date.
3. Set its scope to one that covers **every** target scope you plan to deploy to (every `scopeId` / `scopeLevel`
listed under `targets:` in that console's file).
4. Grant it a role with permission to manage **Custom Rules** and **Perform Advanced Actions** as well if you want
to hide rule logic.
5. Copy the generated API token — this is the only time it's shown — and paste it into the GitHub secret.

> **Note**: Treat the token like a password. This example uses GitHub Actions secrets for simplicity and is not intended to prescribe a particular production credential-management approach.
> You should evaluate and implement the access controls, secret storage, and deployment safeguards appropriate for your environment.
> Securing the token and controlling access to this repository is your responsibility - anyone who can read the token or push to main can change what runs in your SentinelOne console.

### 3. Point a console file at your scope

Edit `consoles/dev-console.yaml` (add one file per console):

```yaml
mgmtUri: https://<your-console>.sentinelone.net   # your console URL
tokenSecret: DAC_API_TOKEN_DEV                    # the GitHub secret from step 2

targets:                         # named scopes that rules are deployed to
  site-rules:
    scopeId: "<site-id>"         # must be a string
    scopeLevel: site             # one of: site, account, global
  account-rules:
    scopeId: "<account-id>"
    scopeLevel: account

deploy:                          # which rule files go to which target
  site-rules:
    - "events/*.yaml"            # globs of rule files, relative to detections/
    - "correlation/*.yaml"
    - "scheduled/*.yaml"
  account-rules:
    - "shared/*.yaml"
```

A `global` target needs no `scopeId` (see `consoles/prod-console.yaml`).

In globs, `*` also matches subfolders, so `shared/*.yaml` covers everything under `shared/`.

Find your `scopeId` in the SentinelOne console or via the API.

> **Note:** The example setup has two consoles (`dev-console.yaml` and `prod-console.yaml`). If you only
> use one, remove the other file.

### 4. Create, update, remove, or import a rule

Each YAML file under `detections/` (matched by a glob in a console file) is one detection rule.
What you do in Git determines what happens in SentinelOne management console:

- **Create** — add a new YAML file (or add a glob in a console file that matches a YAML file not previously deployed).
- **Update** — edit an existing YAML file.
- **Retain** — remove the YAML file (or its glob). With the default `deletePolicy: Retain`, the rule stays in the
  console and is just no longer managed by this repo.
- **Delete** — set `deletePolicy: Delete` in the file and merge, then remove the YAML file (or its glob). The rule
  is deleted from the console.
- **Import** — bring an existing console rule under this repo's control by adding a file with its
  `importCustomRuleId`. The file must match the rule exactly, so download it with
  `GET /web/api/v2.1/cloud-detection/rules/export-vcs` rather than writing it by hand.

For examples, see:
- `detections/shared/` for simple rules.
- `detections/events/`, `detections/correlation/` and `detections/scheduled/` for more advanced rules.
- `detections/imported/` for an import example. Its `importCustomRuleId` is made up, so no console deploys
  that folder.
- `detections/hidden-logic/` for rules with hidden logic.

> **Note:** The `id` field must be **unique within the repository**. It is the key used to match a YAML file to its
> rule in SentinelOne, so duplicates will fail validation and cause the action to fail.

### 5. Open a Pull Request

```bash
git checkout -b my-first-sync
git add consoles/
git add detections/
git commit -m "My first sync"
git push -u origin my-first-sync
```

Open the PR on GitHub. The **Detection as Code** action will run automatically and post a comment per console showing
exactly what will change in your SentinelOne tenant — *no rules are modified yet*.

On a first run, no rules from this repo have been synced to your management console yet, so the diff should list one
**create** for every rule file matched by `deploy:` in the console file — and zero **updates** or **deletes**.

The same summary is also published as a **check run** per console on the commit, visible in the PR's *Checks* tab and
next to the commit SHA.

### 6. Merge to deploy

Once the PR is approved and merged into `main`, the `apply` job runs and your rules go live in SentinelOne.
Check the **Actions** tab for the deployment summary, or the **check-run** posted on the merge commit.

The `apply` summary should match the `diff` summary you saw on the PR exactly — same number of creates, updates,
deletes, imports, and retains, and the same rule IDs in each list.

Before deploying to a production environment, review this workflow against your organization's change-management, credential-management, and CI/CD security requirements.

## Recommended GitHub repository settings

Because a merge to `main` deploys directly to your SentinelOne console, lock the branch down:

- **Branch protection on `main`** (Settings → Branches → Add rule):
  - Require a pull request before merging.
  - Require at least one approving review.
  - Require status checks to pass — select the **Detection as Code / diff (`<console>`)** check for each console.
  - Require branches to be up to date before merging.
- **Disable direct pushes** to `main` and disallow force-pushes and deletions.
- **Disable forking** (Settings → General → Features) so the API token secrets can't leak via a fork's workflows.
- **Limit who can manage Actions secrets/variables** — anyone with write access to a console's token secret can redirect its deployments.

