# DSUtils

A from-scratch recreation of Bohemia Interactive's **DSUtils**, the tools ArmA uses to sign addons, in both C++ and Python.

If you run a server with `verifySignatures` on, every mod's `.pbo` needs a matching `.bisign`, and players need your `.bikey`. These tools make those files, without needing BI's tools installed.

Key files from `dsCreateKey` match the format of BI's originals byte for byte, and are accepted by the original tools.

## Status

| Tool | C++ | Python |
|---|---|---|
| `dsCreateKey` | ✅ | ✅ |
| `dsSignFile` | ✅ | ✅ |
| `dsCheckSignatures` | ❌ not yet | ❌ not yet |

## Usage

Make a key pair (do this once per signing authority, usually your mod tag):

```
dsCreateKey MyTag
```

That gives you two files:

- `MyTag.bikey`: the **public** key. Ship it with your mod, and server owners drop it into their `keys` folder.
- `MyTag.biprivatekey`: the **private** key. **Never share or commit this.** Anyone who has it can sign files as you.

Sign an addon:

```
dsSignFile MyTag.biprivatekey @MyMod\addons\mymod.pbo
```

That writes `mymod.pbo.MyTag.bisign` next to the PBO.

The Python versions take the same arguments:

```
python DSCreateKey.py MyTag
python DSSignFile.py MyTag.biprivatekey mymod.pbo
```

## Downloads

Prebuilt binaries are on the [Releases](../../releases/latest) page. Windows only, since the tools use the Windows CryptoAPI just like the originals.

## Building

**C++:** open `DS.sln` in Visual Studio 2022 and build `Release | x64`, or from a terminal:

```
msbuild DS.sln /p:Configuration=Release /p:Platform=x64
```

**Python:** nothing to build. You need Python 3 on Windows, and there are no extra packages (it calls `advapi32` through `ctypes`).

## About the crypto

The keys are 1024-bit RSA and the signatures use SHA-1. Both are weak by today's standards, but they're **deliberate**: it's what the game expects, and anything stronger simply wouldn't be accepted. Please don't open an issue about it.

## Not affiliated

This project has nothing to do with Bohemia Interactive. "ArmA" and "DSUtils" are their trademarks, used here only to describe what these tools are compatible with.

## License

Apache 2.0, see [LICENSE](LICENSE).
