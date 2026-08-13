# frida-gadget-injector

Injects [Frida Gadget](https://frida.re/docs/gadget/) into an `.ipa`'s main
executable (adds an `LC_LOAD_DYLIB` load command via
[LIEF](https://lief.re/)), so the app loads Frida on launch without a
jailbreak. Runs entirely on a plain `ubuntu-latest` GitHub Actions runner -
no macOS involved for this step at all.

This is for recovering/inspecting **your own** apps (e.g. an old app whose
decrypted source you've lost and only have the encrypted App Store build
left) - not for arbitrary third-party apps.

## Why this approach

The usual "force-decrypt the file on disk" approach (what tools like
`appdecrypt` do, via the private `mremap_encrypted` syscall) gets blocked
with `EPERM` on every virtualized/hosted macOS environment (GitHub Actions,
Bitrise, etc.) - confirmed empirically, see the sibling
[appdecrypt](https://github.com/LackyCraft/appdecrypt) repo's workflow runs.

Frida Gadget injection sidesteps that entirely: instead of forcing
decryption of a static file, you let iOS decrypt the binary the normal,
fully-legitimate way (as part of launching an app you're authorized to
run), then read the already-decrypted memory of the running process. No
private syscalls, no SIP/AMFI fighting.

## What this repo does (and doesn't do)

- **Does:** patch the `.ipa`'s main binary to load `FridaGadget.dylib` on
  startup, and repackage it. Runs on Linux, no macOS needed.
- **Doesn't:** sign the patched `.ipa`. It comes out unsigned on purpose -
  AltStore/Sideloadly/Xcode all strip and re-sign the whole bundle when
  installing to a device anyway, so signing here would just be redone and
  invalidated on install.

## Usage

1. Actions -> "Inject Frida Gadget into IPA" -> Run workflow.
   - `ipa_url`: defaults to the `telegram.ipa` test fixture from the
     `appdecrypt` repo. Point it at your own app's `.ipa` URL to use this
     for real.
   - `output_name`: defaults to `patched.ipa`.
2. Download the `patched-ipa` artifact from the finished run.
3. **Install it on your iPhone** using AltStore (Windows/macOS/Linux
   client available) or Sideloadly, signed with your own free Apple ID.
   No jailbreak needed. This step needs your computer to actually be on
   the same network/USB connection as the phone - it can't be done from a
   cloud runner.
4. Launch the app on the phone. FridaGadget starts a local Frida server
   inside the process automatically.
5. From your computer, with `frida-tools` installed (`pip install
   frida-tools`) and the device connected/paired:
   ```
   frida-ps -U
   ```
   should show the app's process. Then use
   [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) or
   [bagbak](https://github.com/ChiChou/bagbak) against it to pull out a
   genuinely decrypted `.ipa`.

## Status

Step 1 (this repo, the injection) has been tested end-to-end against the
`telegram.ipa` fixture. Steps 3-5 (install/launch/dump) happen on your own
machine against your own physical device and haven't been run yet - come
back with results/errors from those and we'll iterate.
