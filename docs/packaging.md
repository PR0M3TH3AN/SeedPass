# Packaging SeedPass

This guide describes how to build platform-native packages for SeedPass using [BeeWare Briefcase](https://briefcase.readthedocs.io/).

## Prerequisites

* Python 3.12 with development headers (`python3-dev` on Debian/Ubuntu).
* Briefcase installed in your virtual environment:

```bash
pip install briefcase
```

## Linux

The helper script in `packaging/build-linux.sh` performs `briefcase create`, `build`, and `package` for the current project.

```bash
./packaging/build-linux.sh
```

Briefcase outputs its build artifacts in `build/seedpass-gui/ubuntu/noble/`. These files can be bundled in container formats such as Flatpak or Snap. Example manifests are included:

* `packaging/flatpak/seedpass.yml` targets the `org.gnome.Platform` runtime and copies the Briefcase build into the Flatpak bundle.
* `packaging/snapcraft.yaml` stages the Briefcase build and lists GTK libraries in `stage-packages` so the Snap includes its GUI dependencies.

## macOS and Windows

Scripts are provided to document the commands expected on each platform. They must be run on their respective operating systems:

* `packaging/build-macos.sh`
* `packaging/build-windows.ps1`

Each script runs Briefcase's `create`, `build`, and `package` steps with `--no-input`.

## Reproducible Releases

The `packaging/` directory contains the scripts and manifests needed to regenerate desktop packages. Invoke the appropriate script on the target OS, then use the supplied Flatpak or Snap manifest to bundle additional dependencies for Linux.
