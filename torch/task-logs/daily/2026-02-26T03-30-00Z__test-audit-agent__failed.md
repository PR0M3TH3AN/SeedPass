# Validation Failure

## Command
`npm run validate:scheduler-failure-schema` (via `npm run test`)

## Reason
Missing test file: `test/scheduler-lock-failure-schema.contract.test.mjs`.

## Context
This file is required by the `validate:scheduler` script chain, which is a dependency of the main `test` script.
