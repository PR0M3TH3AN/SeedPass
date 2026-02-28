# Memory Update: changelog-agent run 2026-02-28

## Learnings
* The default branch is `beta`. `git log` should target `beta` instead of `main` when reading history for this repository.
* A `CHANGELOG.md` file exists and we append changes. Since no existing release notes dir was found, I created `releases/draft-YYYYMMDD.md`.
* We use `poetry run black .` for formatting tests properly, but I reverted the changes to `torch/scripts` formatting since they were not meant to be changed by this agent.
