# Packaging the GUI with Briefcase

This project uses [BeeWare's Briefcase](https://beeware.org) to generate
platform‑native installers. Once your development environment is set up,
package the GUI by running the following commands from the repository root:

```bash
# Create the application scaffold for your platform
briefcase create

# Compile dependencies and produce a distributable bundle
briefcase build

# Run the packaged application
briefcase run
```

## Command Overview

- **`briefcase create`** — generates the project scaffold for your
  operating system. Run this once per platform.
- **`briefcase build`** — compiles dependencies and produces the
  distributable bundle.
- **`briefcase run`** — launches the packaged application so you can test
  it locally.

After the initial creation step you can repeatedly run `briefcase build`
followed by `briefcase run` to test your packaged application on Windows,
macOS or Linux.
