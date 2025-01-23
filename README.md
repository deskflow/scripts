# Deskflow Development Scripts

Optional development scripts for Deskflow.
To use, clone this repo into your `deskflow` repo.

These scripts are meant only to add developer conveniences during daily development.
They are not used by CI and are not required at all for Deskflow development.

## References

The [`.vscode`](https://github.com/deskflow/.vscode) project references scripts in this project.

This project is intended to be used with the example 
[`CMakeUserPresets.json`](https://gist.github.com/nbolton/1a6c59b576528f20f76ae2e3fd0c72d5) 
file, which installs to `build/install` on Windows.

> [!TIP]
> On Windows, you may find that you have a more pleasant development experience if you run from
> `build/install` rather than `build/bin`  to avoid "Access denied: file in use" errors.
