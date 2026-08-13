#!/usr/bin/env python3
"""
Injects FridaGadget.dylib into an iOS app's main executable by adding an
LC_LOAD_DYLIB load command (via LIEF), so the app loads Frida on launch
without needing a jailbreak. Signing is intentionally NOT done here -
AltStore/Sideloadly/Xcode strips and re-signs the whole bundle on install
anyway, so an unsigned intermediate .ipa is the right handoff point.
"""
import argparse
import pathlib
import shutil
import sys
import zipfile

import lief


def find_app_dir(payload_dir: pathlib.Path) -> pathlib.Path:
    apps = [p for p in payload_dir.iterdir() if p.suffix == ".app"]
    if not apps:
        raise SystemExit(f"No .app bundle found under {payload_dir}")
    return apps[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa_in", type=pathlib.Path)
    parser.add_argument("gadget_dylib", type=pathlib.Path)
    parser.add_argument("ipa_out", type=pathlib.Path)
    args = parser.parse_args()

    work = pathlib.Path("_gadget_work")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()

    print(f"[*] Extracting {args.ipa_in}")
    with zipfile.ZipFile(args.ipa_in) as zf:
        zf.extractall(work)

    payload_dir = work / "Payload"
    app_dir = find_app_dir(payload_dir)
    app_name = app_dir.stem
    main_binary = app_dir / app_name
    if not main_binary.exists():
        raise SystemExit(f"Expected main binary at {main_binary}, not found")

    frameworks_dir = app_dir / "Frameworks"
    frameworks_dir.mkdir(exist_ok=True)
    gadget_dest = frameworks_dir / "FridaGadget.dylib"
    shutil.copy(args.gadget_dylib, gadget_dest)
    print(f"[*] Copied Frida Gadget to {gadget_dest}")

    print(f"[*] Loading {main_binary} with LIEF")
    fat = lief.MachO.parse(str(main_binary))
    if fat is None:
        raise SystemExit(f"LIEF could not parse {main_binary}")

    load_path = "@executable_path/Frameworks/FridaGadget.dylib"
    for binary in fat:
        existing = [
            c.name for c in binary.libraries
            if hasattr(c, "name")
        ]
        if load_path in existing:
            print(f"[*] {binary.header.cpu_type} slice already has the gadget load command, skipping")
            continue
        binary.add_library(load_path)
        print(f"[*] Added LC_LOAD_DYLIB for {load_path} to {binary.header.cpu_type} slice")
        # Drop the now-invalid signature; AltStore/Sideloadly/etc. re-sign
        # the whole bundle on install regardless.
        try:
            binary.remove_signature()
        except Exception as e:
            print(f"[*] remove_signature: {e} (probably wasn't signed, fine)")

    fat.write(str(main_binary))
    print(f"[*] Wrote patched binary to {main_binary}")

    if args.ipa_out.exists():
        args.ipa_out.unlink()
    print(f"[*] Repackaging to {args.ipa_out}")
    with zipfile.ZipFile(args.ipa_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in work.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(work))

    print("[+] Done.")
    print(f"    Patched, UNSIGNED ipa: {args.ipa_out}")
    print("    Next: install via AltStore/Sideloadly/Xcode under your own")
    print("    Apple ID - they re-sign the whole bundle on install, which")
    print("    is required for this to actually launch.")


if __name__ == "__main__":
    main()
