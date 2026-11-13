# Dependency notices

Latch's own source is MIT licensed. Its dependencies retain their respective
licenses and attribution. Both executables carry a compressed notice bundle:

```sh
latch licenses --output client-notices.zip
latch-server licenses --output server-notices.zip
```

These commands work offline and refuse to overwrite an existing file. The ZIP
contains original notice files, Latch's MIT license, Go notices and, for the
client, Rust standard-library notices and crate metadata with source references.
MPL-covered dependencies' unmodified source archives are identified by exact
crate name/version in each `PACKAGE.json`; patched Git dependencies identify
their pinned repository revision. Preserve these references when redistributing.

Regenerate using the pinned Go and Rust toolchains, from the repository root:

```sh
go -C tools/release run . notices --source "$PWD" --component client
go -C tools/release run . notices --source "$PWD" --component server
```

Append `--check` to compare without writing. The normal local verification script
checks both bundles, and the release builder checks its selected component.
Go collection uses the executable dependency union across supported platforms.
Rust collection conservatively includes the full locked graph, including build,
test and inactive-platform dependencies. Inclusion does not mean every package
is linked into a particular executable. ZIP entries are sorted, timestamps fixed,
and local source/cache paths excluded.

Some published crate archives omit their declared license files. Reviewed
exceptions match the recorded crate source revision and declared license:

| Local original text | Source |
|---|---|
| `licenses/MPL-2.0.txt` | [Mozilla MPL 2.0 text](https://www.mozilla.org/media/MPL/2.0/index.txt), for HPKE 0.8.0 crates at `42d68bd49b244b09bd02626c6ffa95e54dc64f91` |
| `licenses/Libcrux-42d68bd.txt` | [libcrux repository license](https://raw.githubusercontent.com/celabshq/libcrux/42d68bd49b244b09bd02626c6ffa95e54dc64f91/LICENSE) |
| `licenses/OpenMLS-0.9.2.txt` | [OpenMLS crate source revision](https://raw.githubusercontent.com/openmls/openmls/8a8f83b4b61fc45f28facec25e914992b3465de6/LICENSE) |
| `licenses/OpenMLS-serialization-0.1.0.txt` | [Serialization helper source revision](https://raw.githubusercontent.com/openmls/openmls/3a3e35de3feeca8f6605143c464d5452ae584d43/LICENSE) |

An unmatched missing notice fails generation; the tool does not invent a license
or copyright holder. Review exceptions when updating dependencies.
