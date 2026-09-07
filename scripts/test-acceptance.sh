#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checkout="${1:-${ENTORN_BAGISTO_CHECKOUT:-}}"
expected_revision="aa544167182b3503c08a3b27981288d1921fbf4d"

[[ -n "$checkout" ]] || {
  echo "Usage: scripts/test-acceptance.sh /path/to/bagisto@$expected_revision" >&2
  exit 2
}
[[ -d "$checkout/.git" ]] || { echo "Bagisto checkout is not a Git worktree: $checkout" >&2; exit 2; }
actual_revision="$(git -C "$checkout" rev-parse HEAD)"
[[ "$actual_revision" == "$expected_revision" ]] || {
  echo "Bagisto checkout must be exactly $expected_revision (found $actual_revision)." >&2
  exit 2
}
[[ -z "$(git -C "$checkout" status --porcelain --untracked-files=all)" ]] || {
  echo "Bagisto checkout must be clean so the pinned corpus is exact." >&2
  exit 2
}

export ENTORN_BAGISTO_CHECKOUT="$(cd "$checkout" && pwd)"
dotnet test "$repo_root/tests/Archie.Scanner.Php.Tests/Archie.Scanner.Php.Tests.csproj" \
  --configuration Release \
  --no-restore \
  --filter FullyQualifiedName~PublicCorpusAcceptanceTests
