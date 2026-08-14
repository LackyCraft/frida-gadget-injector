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

    # The Watch companion app (Telegram.app/Watch/*.app) is a double
    # liability: (1) its Mach-O is a fat/universal binary that crashed
    # appdecrypt's naive parser early on, and (2) its Info.plist's
    # WKCompanionAppBundleIdentifier points at the *original* bundle ID.
    # Sideloadly (and any resigner that changes the bundle ID, which most
    # do to dodge collisions) doesn't update that nested reference, so the
    # installer rejects the whole ipa with InvalidCompanionAppBundleIdentifier
    # - confirmed live via Sideloadly's install log on this exact file. We
    # don't need the Watch app for dumping the main binary under Frida, so
    # just remove it rather than trying to patch its Info.plist to track
    # whatever ID the resigner ends up choosing.
    watch_dir = app_dir / "Watch"
    if watch_dir.is_dir():
        shutil.rmtree(watch_dir)
        print("[*] Removed Watch companion app (avoids InvalidCompanionAppBundleIdentifier on resign)")
    else:
        print("[*] No Watch companion app present, nothing to remove")

    # App extensions (Share, Widget, NotificationService, Intents,
    # BroadcastUpload, etc.) each get their own App ID + provisioning
    # profile during local free-tier resigning, and several of them share
    # an App Group container with the main app for cross-process data.
    # Confirmed empirically: two independent complex multi-extension apps
    # (Telegram, Spotify) both install "successfully" via Sideloadly
    # (100% Complete) but then fail to actually launch (icon/splash then
    # immediate close) - identical behavior on a *control* build with zero
    # Mach-O changes, ruling out our LIEF patching. A control build of
    # Spotify with only the Watch app removed still failed. Since we only
    # need the *main* binary to dump under Frida, stripping every
    # extension removes the whole multi-target App Group signing surface
    # rather than trying to chase whatever entitlement mismatch a free
    # account's local resigning produces across N separately-provisioned
    # targets.
    plugins_dir = app_dir / "PlugIns"
    if plugins_dir.is_dir():
        removed_ext = sorted(p.name for p in plugins_dir.iterdir())
        shutil.rmtree(plugins_dir)
        print(f"[*] Removed {len(removed_ext)} app extension(s) from PlugIns: {removed_ext}")
    else:
        print("[*] No PlugIns directory present, nothing to remove")

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

        # Confirmed live on-device: launchd refuses to spawn the process at
        # all ("Launchd job spawn failed", POSIX 80) while LC_ENCRYPTION_INFO_64
        # still declares cryptid=1 and we have no valid FairPlay key material
        # (SC_Info was removed - it broke installation, see above) for the
        # kernel to decrypt against. Zeroing cryptid does NOT decrypt the
        # actual __TEXT bytes - they stay ciphertext - but it stops the
        # kernel from refusing to exec() the binary at all. dyld runs every
        # loaded dylib's constructors (including FridaGadget's) before
        # jumping into the main executable's own entry point, so Frida gets
        # a window to attach even though the app's own code is still
        # garbage and will crash once it's reached.
        # NOTE: LIEF's Python binding names this field `crypt_id` (with an
        # underscore), NOT `cryptid` like the raw Mach-O struct/most docs.
        # An earlier version of this script used `cryptid`, which silently
        # no-opped via getattr(..., 0)'s default instead of raising - so it
        # always reported "already 0" and never actually touched anything.
        # Confirmed directly: both Telegram's and Spotify's main binaries
        # have crypt_id == 1, matching the observed "installs fine, closes
        # instantly on launch" behavior on every build tested so far (this
        # "fix" was a no-op the whole time).
        enc_info = getattr(binary, "encryption_info", None)
        if enc_info is not None and getattr(enc_info, "crypt_id", 0) != 0:
            print(f"[*] Found LC_ENCRYPTION_INFO_64 with crypt_id={enc_info.crypt_id}, zeroing it "
                  f"(binary stays encrypted, this only unblocks exec())")
            enc_info.crypt_id = 0
        elif enc_info is not None:
            print(f"[*] LC_ENCRYPTION_INFO_64 present, crypt_id already {enc_info.crypt_id}")
        else:
            print("[*] No LC_ENCRYPTION_INFO_64 on this slice")

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

    # Apple's App Store CDN stamps the ipa root with META-INF/
    # com.apple.ZipMetadata.plist (+ .bin), which records the *original*
    # RecordCount and TotalUncompressedBytes for the archive. We add a file
    # and change another's size, so those recorded numbers no longer match
    # reality - and this is exactly what tools like iMazing check to
    # detect "tampering" (its error fired even after the _CodeSignature
    # fix, on this exact file). There's no public spec for recomputing
    # ZipTool's metadata correctly, so - same call as _CodeSignature -
    # just drop the now-stale directory rather than ship wrong values.
    meta_inf = work / "META-INF"
    if meta_inf.is_dir():
        shutil.rmtree(meta_inf)
        print("[*] Removed stale META-INF (com.apple.ZipMetadata.plist) directory")
    else:
        print("[*] No META-INF directory present, nothing to remove")

    # SC_Info/*.sinf holds the original FairPlay DRM license blob for the
    # app - confirmed live on-device (libcopyfile.dylib) that install fails
    # with EPERM trying to open() this exact file while staging the app for
    # (re)signing. FairPlay SINF handling is privileged/Apple-only; a
    # sideloaded, locally re-signed app has no business with it. Same
    # treatment as the other two stale-signing-artifact directories.
    removed_sc_info = 0
    for sc_info_dir in work.rglob("SC_Info"):
        if sc_info_dir.is_dir():
            shutil.rmtree(sc_info_dir)
            removed_sc_info += 1
    print(f"[*] Removed {removed_sc_info} stale SC_Info director{'y' if removed_sc_info == 1 else 'ies'}")

    gadget_arcname = str(gadget_dest.relative_to(work))
    executable_new_files = {gadget_arcname}

    # The original ipa has ~110 explicit directory entries (arcnames ending
    # in "/", zero-length). Our rglob loop used to skip everything that
    # wasn't a file, so the repackaged zip had *zero* directory entries -
    # confirmed by comparing directly against the source zip's namelist().
    # A control build (identical to this one but with zero Mach-O changes)
    # still failed to launch after Sideloadly resigning, which ruled out
    # the LIEF patching as the cause and pointed back at the repackaging
    # step itself - this is the most concrete structural difference found,
    # so directories are now written explicitly too.
    if args.ipa_out.exists():
        args.ipa_out.unlink()
    print(f"[*] Repackaging to {args.ipa_out}")
    with zipfile.ZipFile(args.ipa_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(work.rglob("*")):
            if path.is_dir():
                arcname = str(path.relative_to(work)) + "/"
                info = zipfile.ZipInfo(arcname)
                info.compress_type = zipfile.ZIP_STORED
                if arcname in original_attrs:
                    info.external_attr = original_attrs[arcname]
                else:
                    info.external_attr = (0o040755 << 16) | 0x10
                zf.writestr(info, b"")
                continue
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
