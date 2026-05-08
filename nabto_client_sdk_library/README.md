# nabto-client-sdk-releases

This repo replaces the [Nabto5-releases](https://github.com/nabto/nabto5-releases) repo for releases of the Nabto Client SDK library from v5.12.0. Earlier releases are still available in the original repo.

This repo only has a single set of artifacts checked in. When a Nabto Client SDK library is released, the artifacts in this repo will be updated, and the repo will be tagged for the particular release.

The latest release artifacts can always be downloaded from the [releases page](https://github.com/nabto/nabto-client-sdk-releases/releases/latest).

## Windows libraries.

The windows libraries depends on msvcp140.dll and vcruntim140.dll
these are dll's your custom application probably also needs. See
https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170
and
https://learn.microsoft.com/en-US/cpp/windows/redistributing-visual-cpp-files?view=msvc-170
