# Testing Strategy

## Unit Tests

Unit tests validate small pieces of logic such as:

- parsers
- validators
- risk rules
- scoring
- command execution wrappers
- console and safe-exit helpers

## Integration Tests

Integration tests check how the modules work together. They verify:

- the fallback flow
- the test-mode pipeline
- the production-mode pipeline
- report generation

## Mock Data

Mock data is used to keep test mode safe and deterministic. It allows the
pipeline to run end-to-end without touching live logs or real system exports.

## Test Mode

Test mode is the preferred way to verify the full pipeline locally. It should
produce reports and alerts from controlled evidence.

## Manual Test Cases

Useful manual checks include:

- `python app.py --test`
- `python app.py --mode test`
- `python app.py --mode linux`
- `python app.py --mode windows`

These checks help confirm that the orchestrator, collectors, fallback logic,
and reporting flow still behave as expected.
