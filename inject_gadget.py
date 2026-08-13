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
        # zipfile.write()/extractall() do NOT reliably round-trip unix
        # permission bits (external_attr) - if the repackaged executable
        # loses its +x bit, installers can choke on it (this is a known
        # cause of on-device installer crashes). Remember the original
        # per-entry external_attr so we can restore it for unmodified
        # files below.
        original_attrs = {info.filename: info.external_attr for info in zf.infolist()}
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

    # Every signable bundle (the main .app, each .framework/.appex, and any
    # nested .app like a Watch companion) carries its own
    # _CodeSignature/CodeResources - a manifest of hashes over every file in
    # that bundle. We changed the main binary and added a new file, so the
    # main app's manifest is now stale and no longer matches reality.
    # Installers/validators that check it (iMazing does; SideStore
    # apparently doesn't) will flag the ipa as "tampered". Since every
    # sideload path re-signs the whole bundle anyway (which regenerates
    # these), just strip the stale ones instead of trying to recompute them.
    removed = 0
    for sig_dir in work.rglob("_CodeSignature"):
        if sig_dir.is_dir():
            shutil.rmtree(sig_dir)
            removed += 1
    print(f"[*] Removed {removed} stale _CodeSignature director{'y' if removed == 1 else 'ies'}")

    gadget_arcname = str(gadget_dest.relative_to(work))
    executable_new_files = {gadget_arcname}

    if args.ipa_out.exists():
        args.ipa_out.unlink()
    print(f"[*] Repackaging to {args.ipa_out}")
    with zipfile.ZipFile(args.ipa_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(work.rglob("*")):
            if not path.is_file():
                continue
            arcname = str(path.relative_to(work))
            info = zipfile.ZipInfo(arcname)
            info.compress_type = zipfile.ZIP_DEFLATED
            if arcname in original_attrs:
                # Unmodified (or content-modified but not new) file - keep
                # whatever permissions/flags it had in the source ipa.
                info.external_attr = original_attrs[arcname]
            elif arcname in executable_new_files:
                # New file we added ourselves (the gadget dylib) - needs
                # the executable bit or dyld/the installer can reject it.
                info.external_attr = (0o100755 << 16)
            else:
                info.external_attr = (0o100644 << 16)
            zf.writestr(info, path.read_bytes())
    print(f"[*] Preserved original permissions for {len(original_attrs)} entries, "
          f"set 755 on {len(executable_new_files)} new file(s)")

    print("[+] Done.")
    print(f"    Patched, UNSIGNED ipa: {args.ipa_out}")
    print("    Next: install via AltStore/Sideloadly/Xcode under your own")
    print("    Apple ID - they re-sign the whole bundle on install, which")
    print("    is required for this to actually launch.")


if __name__ == "__main__":
    main()
