# Packaging Sangward

This directory holds the freedesktop integration files and the Arch Linux
packaging recipes.

## Contents

- `dev.sangward.Sangward.desktop` — the desktop entry, installed to
  `/usr/share/applications/`.
- `dev.sangward.Sangward.svg` — the icon, installed to
  `/usr/share/icons/hicolor/scalable/apps/`.
- `aur/sangward/` — PKGBUILD that builds from the `v<version>` source archive.
- `aur/sangward-bin/` — PKGBUILD that installs the prebuilt release tarball.

The file names and the `Icon=` key must stay in sync with the GTK application
ID `dev.sangward.Sangward` (`APP_ID` in `crates/sangward-gtk/src/app.rs`).

The two files are the single source of truth for desktop integration. The
release workflow copies them into the release tarball, and the source archive
contains them under `packaging/`, so the AUR recipes install them from the
downloaded sources instead of carrying their own copies.

## Building a package locally

```sh
cd aur/sangward-bin   # or: cd aur/sangward
makepkg -si
```

The source package runs `cargo fetch` (network) in `prepare()`, then an
offline, locked release build in `build()`.

## Publishing to the AUR

The AUR does not accept binary uploads: you push a git repository containing
the PKGBUILD plus every file it references. Sources must be **publicly**
reachable.

Initial upload, once the package name is free:

```sh
git clone ssh://aur@aur.archlinux.org/sangward.git
cp PKGBUILD .SRCINFO sangward/
cd sangward
git add PKGBUILD .SRCINFO
git commit -m "sangward 0.1.1-1"
git push
```

Repeat with `sangward-bin.git` for the binary package.

Updating for a new release:

```sh
# Bump pkgver in the PKGBUILD and reset pkgrel to 1, then:
updpkgsums
makepkg --printsrcinfo > .SRCINFO
```

`updpkgsums` downloads the sources to compute checksums, so the GitHub
repository (and, for `sangward-bin`, the release asset) must be public for the
build to work for everyone. Both packages' `sha256sums` are refreshed right
after a release is published.

## Release checklist

1. Bump `version` in the root `Cargo.toml`, commit, and push a matching tag.
2. Wait for the Release workflow to publish the tarball.
3. Bump `pkgver` in both PKGBUILDs, run `updpkgsums`, regenerate `.SRCINFO`,
   and push to the AUR.
