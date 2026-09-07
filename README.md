# Entorn PHP scanner

First-party scanner for Composer projects, Laravel applications and routes, package dependencies, and source ownership. The scanner is implemented as a .NET worker; “PHP scanner” describes the target technology.

The worker implements the language-neutral [`scanner/v1` protocol](https://github.com/Entorn-dev/entorn-scanner-contracts). Its historical `archie.php` scanner identity remains unchanged in the first Entorn release so existing installations and deterministic observations remain compatible during the wider product rename.

## Build and test

```bash
dotnet restore --locked-mode --runtime linux-x64
dotnet test --no-restore --configuration Release
```

## Package

```bash
scripts/package-linux-x64.sh 2.0.0
```

The script produces a deterministic `tar.gz` and SHA-256 file under `artifacts/`. The archive contains no signing key. An approved release is signed offline and admitted to the signed scanner catalog separately.

The scanner reads repository files but does not execute PHP, Composer, Artisan, or other target code, use the network, or inherit repository-controlled environment configuration. It applies repository `.gitignore` files during traversal, before file-count and byte limits, so ignored generated/build output is not scanner input. Ignore rules are evaluated deterministically from repository content only; global Git configuration and `.git/info/exclude` are not consulted. PHP semantic inputs are limited to files owned by Composer production `autoload.psr-4` roots plus route files for safely classified Laravel applications. Blade templates (`*.blade.php`) and unrelated PHP trees are not supported architecture-evidence sources and do not enter scanner input or syntax budgets. Every eligible PHP input remains subject to the 2 MiB per-file and fixed syntax-tree limits, and exceeding either fails the whole worker without partial observations; syntax-node diagnostics identify the eligible repository-relative file and whether the per-file or aggregate budget was exceeded.

## License and contributions

Licensed under Apache-2.0. Contributions require Developer Certificate of Origin sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
