#!/usr/bin/env python3
"""PE-Reborn AOSP17 matrix row 174 — source-only NXP SE AIDL/HIDL audit.

No Soong, OTA, APDU, SE firmware/provisioning, real hardware or device VINTF.
"""
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

LEGACY_SHA = "a171c5ad0105d650d471268733b48d22584cb64a"
LEGACY_TREE = "30c1feabe1d5107268ab21494ae4243436e52562"
AOSP_SHA = "ebc3542b480e505ed67ec52ea0c3135e5902ff5e"
AOSP_TREE = "32593f6a857cc48d52ec6f5c8e7799be2434d6b1"
SEC_SHA = "8aec22fde8121bf3f74006730ce42e9ac0366b62"
SEC_TREE = "60db7cd2fb71673b3d8468162eaaed6649e3c42c"
NXP_SHA = "582d149bebb97e01ec071bbcfa9a05e356958f50"
NXP_TREE = "c492237788bf4f0c638d0ae1a352791cdc5eaf1a"
LEGACY_PATH = "vendor/nxp/secure_element"
LEGACY_NAME = "vendor_nxp_secure_element"
SE_SOURCE = "hardware/nxp/secure_element"
OMAPI_SOURCE = "system/secure_element"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True, stderr=subprocess.PIPE).strip()


def pin(root, ref, commit, tree, title):
    got = git(root, "rev-parse", f"{ref}^{{commit}}")
    require(got == commit, f"{title}: unexpected commit {got}")
    got_tree = git(root, "rev-parse", f"{got}^{{tree}}")
    require(got_tree == tree, f"{title}: unexpected tree {got_tree}")
    return got


def show(root, rev, path):
    return git(root, "show", f"{rev}:{path}")


def blob_paths(root, sha, prefix):
    result = {}
    tree_args = ["ls-tree", "-r", sha] + ([prefix] if prefix else [])
    for line in git(root, *tree_args).splitlines():
        header, path = line.split("\t", 1)
        _mode, kind, blob = header.split()
        if kind == "blob":
            result[path] = blob
    return result


def legacy_secure_element(root):
    ref = pin(root, "refs/remotes/origin/seventeen",
              LEGACY_SHA, LEGACY_TREE, "legacy 2023 NXP SE HIDL")
    files = blob_paths(root, ref, "")
    require(len(files) == 83,
            f"legacy SE source inventory changed: {len(files)}")
    bp = show(root, ref, "Android.bp")
    prod = show(root, ref, "se-vendor-product.mk")
    service = show(root, ref, "1.2/NxpEseService.cpp")
    vintf = ET.fromstring(
        show(root, ref, "1.2/android.hardware.secure_element@1.2-service.p73.xml"))
    rc = show(root, ref, "1.2/android.hardware.secure_element@1.2-service.p73.rc")
    old_vendor = show(root, ref, "extns/impl/NxpEse.cpp")
    updater = show(root, ref, "ese-clients/src/SpiEseUpdater.cpp")
    config = show(root, ref, "libese-spi/p73/libese-nxp-P73.conf")
    policy = show(root, ref, "sepolicy/file_contexts")
    matrix = ET.fromstring(
        show(root, ref, "vendor_framework_compatibility_matrix.xml"))

    for token in ('name: "ese_spi_nxp.p73"',
                  'name: "ls_client.p73"',
                  'name: "android.hardware.secure_element@1.2-service.p73"',
                  'name: "vendor_nxp_secure_element_license"',
                  "vendor/nxp/nfc", '"android.hardware.secure_element@1.2"',
                  '"vendor.nxp.nxpese@1.0"',
                  '"vendor.nxp.nxpnfc@2.0"',
                  '"vendor.nxp.nxpnfclegacy@1.0"',
                  '"vendor.nxp.eventprocessor@1.0"'):
        require(token in bp,
                "archived HIDL eSE HAL module/dependency drift: " + token)
    require("PRODUCT_PACKAGES" in prod
            and "android.hardware.secure_element@1.2-service.p73" in prod
            and "android.hardware.nfc.ese.xml" in prod
            and "android.hardware.se.omapi.ese.xml" in prod
            and "libese-nxp-P73.conf" in prod,
            "old NXP vendor SE feature/config installation changed")
    declared = {}
    for hal in vintf.findall("hal"):
        declared[hal.findtext("name")] = {
            "format": hal.attrib.get("format"),
            "version": hal.findtext("version"),
            "interfaces": {
                i.findtext("name"): {
                    e.text for e in i.findall("instance")
                } for i in hal.findall("interface")
            },
        }
    require(declared["android.hardware.secure_element"] == {
        "format": "hidl", "version": "1.2",
        "interfaces": {"ISecureElement": {"eSE1", "SIM1", "SIM2"}}
    }, "legacy eSE/SIM1/SIM2 HIDL VINTF declaration changed")
    for name in ("vendor.nxp.eventprocessor", "vendor.nxp.nxpese"):
        require(declared[name]["format"] == "hidl"
                and declared[name]["version"] == "1.0",
                "legacy proprietary HIDL SE extension changed: " + name)
    require("ISecureElement eSE1" in rc
            and "vendor.nxp.eventprocessor@1.0::INxpEseEvtProcessor" in rc,
            "archived HIDL service init/VINTF changed")
    for symbol in ("checkIfEseClientUpdateReqd();", "doEseUpdateIfReqd(",
                   'EseConfig::getString(NAME_NXP_SPI_TERMINAL_NAME, "eSE1")',
                   "se_service->registerAsService(spiTermName.c_str())"):
        require(symbol in service,
                "legacy eSE HIDL startup/JCOP behavior changed: " + symbol)
    for fn in ("SpiEseUpdater::checkIfEseClientUpdateReqd(",
               "SpiEseUpdater::doEseUpdateIfReqd(",
               "SpiEseUpdater::handleJcopOsDownload("):
        require(fn in updater,
                "old SPI/NFC eSE updater capability changed: " + fn)
    # Security review, not a vulnerability claim. The JCOP branch copies
    # native struct bytes from HIDL without visible size >= native struct.
    for token in ("NxpEse::ioctl(", "&inOutData[0]",
                  "HAL_ESE_IOCTL_NFC_JCOP_DWNLD",
                  "memcpy(&inpOutData, pInOutData, sizeof(ese_nxp_IoctlInOutData_t))"):
        require(token in old_vendor,
                "legacy HIDL ioctl bounds review signal changed: " + token)
    for token in ('NXP_ESE_DEV_NODE="/dev/p73"',
                  "NXP_POWER_SCHEME=0x02",
                  "NXP_SPI_INTF_RST_ENABLE=0x01"):
        require(token in config,
                "old P73 example settings changed: " + token)
    require("/dev/p73" in policy,
            "old P73 device file contexts changed")
    require(matrix.get("type") == "framework"
            and {h.findtext("name") for h in matrix.findall("hal")}
            == {"vendor.nxp.nxpese", "vendor.nxp.eventprocessor"},
            "old vendor HIDL framework FCM unexpectedly changed")
    print("PASS: historical 83-file NXP P73 HIDL SE 1.2 / nxpese/eventprocessor")
    print("PASS: old VINTF declares eSE1+SIM1+SIM2 but registration is SPI eSE1")
    print("PASS: legacy startup eSE updater and P73 config/SELinux reviewed")
    print("WARN: archived NxpEse::ioctl JCOP/native struct copy needs bounds audit")
    print("NOT CLAIMED: a shipped vulnerability, financial/eSE firmware compatibility")


def check_modern_contract(root, revision, label):
    bp = show(root, revision, "snxxx/aidl/Android.bp")
    vintf = ET.fromstring(
        show(root, revision, "snxxx/aidl/secure_element-service-nxp.xml"))
    for token in ('name: "android.hardware.secure_element-service.nxp"',
                  '"android.hardware.secure_element-V1-ndk"',
                  '"vendor.nxp.nxpnfc_aidl-V1-ndk"',
                  '"libbinder_ndk"',
                  'vintf_fragments: ["secure_element-service-nxp.xml"]'):
        require(token in bp, f"{label} SE AIDL V1 module drift: {token}")
    desired = {
        (h.findtext("name"), h.findtext("version"),
         h.findtext("fqname"), h.attrib.get("format"))
        for h in vintf.findall("hal")
    }
    require(desired == {
        ("android.hardware.secure_element", "1",
         "ISecureElement/eSE1", "aidl")
    }, f"{label} SE VINTF must declare one AIDL V1 eSE1")
    # AIDL service still links NFC HIDL compat: don't assume that source
    # migration removes all legacy dependencies or builds on device.
    require('"android.hardware.nfc@1.2"' in bp,
            f"{label} SE/NFC legacy compat dependencies changed")
    service = show(root, revision, "snxxx/aidl/NxpEseService.cpp")
    require("AServiceManager_addService(" in service
            and "android.hardware.nfc.INfc/default" in service,
            f"{label} SE service registration/NFC dependency changed")
    print(f"PASS: {label} native SE AIDL V1 eSE1, NDK Binder, NFC HAL dependency")
    print(f"INFO: {label} still has NFC HIDL1.2 shared-lib compatibility link")
    return bp


def contemporary_nxp(root):
    ref = pin(root, "refs/remotes/origin/br_ar_17_aosp_mainline",
              NXP_SHA, NXP_TREE, "NXP 17.07.00 secure element")
    readme = show(root, ref, "README.md")
    require("android-17.0.0_r1" in readme
            and "17.07.00" in readme,
            "current NXP17 SE release identity changed")
    check_modern_contract(root, ref, "current NXP17 vendor")
    # The immutable July vendor snapshot predates the official SE security
    # bounds guard. Never accidentally copy its unchecked channel handling.
    for path in ("snxxx/aidl/SecureElement.cpp",
                 "snxxx/aidl/VirtualISO.cpp"):
        vendor_cpp = show(root, ref, path)
        require("mOpenedChannels[resApduBuff.channelNumber] = true"
                in vendor_cpp
                and "rspApdu.p_data[0] < mMaxChannelCount" not in vendor_cpp,
                f"NXP17 SE channel-boundary status changed: {path}")
    print("WARN: pinned NXP17 vendor SE AIDL lacks AOSP17 r3 channel index guard")
    disabled = show(root, ref,
                    "libese_vendor_extn/se_update_agent/Android.bp")
    rc = show(root, ref,
              "libese_vendor_extn/se_update_agent/se_update_agent.nxp.rc")
    hidl_bp = show(root, ref, "snxxx/1.2/Android.bp")
    sems = show(root, ref, "frameworks/sems/Android.bp")
    for text, label in (
        (disabled, "new SE updater"), (hidl_bp, "legacy 1.2 SE service"),
        (sems, "SEMS Java framework"),
    ):
        require("enabled: false" in text,
                f"NXP17 {label} no longer disabled by default")
    require('name: "se_update_agent.nxp"' in disabled
            and '"android.se.omapi-V1-ndk"' in disabled,
            "NXP17 isolated SE updater design changed")
    require("on fs" in rc
            and "start se_update_agent" in rc
            and "vendor.se_update_agent.run_execute" in rc,
            "SE update agent init triggers need re-review")
    require('name: "android.hardware.secure_element_snxxx@1.2-service"' in hidl_bp
            and 'defaults: ["hidl_defaults"]' in hidl_bp,
            "current NXP17 disabled HIDL compatibility service changed")
    print("PASS: current NXP17 updater, old HIDL1.2 and SEMS disabled by default")
    print("WARN: updater init rc is state-mutating if product overrides module")
    return ref


def official_aosp17(root):
    baseline = pin(root, "refs/tags/android-17.0.0_r1",
                   AOSP_SHA, AOSP_TREE, "official AOSP17 NXP SE HAL")
    security = pin(root, "refs/tags/android-security-17.0.0_r3",
                   SEC_SHA, SEC_TREE, "official AOSP17 SE security tag r3")
    check_modern_contract(root, baseline, "official AOSP17 r1")
    # Real official security fix: guard SE response channel before indexing
    # mOpenedChannels. AIDL V1 and both VirtualISO implementations matter.
    for path in ("snxxx/aidl/SecureElement.cpp",
                 "snxxx/aidl/VirtualISO.cpp"):
        before_cpp = show(root, baseline, path)
        after_cpp = show(root, security, path)
        guard = "rspApdu.p_data[0] < mMaxChannelCount && rspApdu.p_data[0] > 0"
        require(guard not in before_cpp
                and "mOpenedChannels[resApduBuff.channelNumber] = true" in before_cpp,
                f"AOSP17 r1 SE channel-index status changed: {path}")
        require(guard in after_cpp
                and "mOpenedChannels[resApduBuff.channelNumber] = true" in after_cpp
                and "sestatus = ISecureElement::CHANNEL_NOT_AVAILABLE" in after_cpp,
                f"official SE security r3 channel bounds fix missing: {path}")
    print("PASS: official SE r3 fixes AIDL SecureElement and VirtualISO channel indices")
    # Check tag by Git file hashes, not release timestamp. Never
    # silently enable a security tag in the current manifest.
    before = blob_paths(root, baseline, "")
    after = blob_paths(root, security, "")
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(p for p in before.keys() & after.keys()
                     if before[p] != after[p])
    print("INFO: AOSP17 r1 -> security-r3 Git source delta:"
          f" changed={len(changed)}, added={len(added)}, removed={len(removed)}")
    for path in (changed + added + removed)[:16]:
        print("INFO: security tag source path: " + path)
    if (changed or added or removed):
        check_modern_contract(root, security, "official SE security r3")
        print("DECISION: newer SE files are review candidates, not active pins")
    else:
        print("DECISION: no SE source-file changes; tag date is not an SE fix")
    return baseline


def source_delta(official_root, official_revision, vendor_root):
    off = blob_paths(official_root, official_revision, "snxxx")
    vendor = blob_paths(vendor_root, NXP_SHA, "snxxx")
    same_names = set(off) & set(vendor)
    different = sorted(p for p in same_names if off[p] != vendor[p])
    official_only = sorted(set(off) - set(vendor))
    vendor_only = sorted(set(vendor) - set(off))
    print("INFO: AOSP17 vs NXP17 actual SNXXX SE blob delta:"
          f" common={len(same_names)}, changed={len(different)},"
          f" official-only={len(official_only)}, NXP-only={len(vendor_only)}")
    for name in different[:8]:
        print("INFO: changed SE source: " + name)
    for name in official_only[:6]:
        print("INFO: official-only SE source: " + name)
    require("snxxx/aidl/Android.bp" in same_names,
            "source comparison missing modern common SE service")


def manifest(root):
    root = Path(root)
    d = ET.parse(root / "default.xml").getroot()
    require(len(d) == 1 and d[0].tag == "include"
            and d[0].get("name") == "aosp17_pe_p2_kernel_configs.xml",
            "active default source-only entrypoint changed")
    p = ET.parse(root / "aosp17_pe_bootstrap.xml").getroot()
    owners = {x.get("path"): x.get("name") for x in p.findall("project")}
    for path, name in (
        ("hardware/nxp/secure_element", "platform/hardware/nxp/secure_element"),
        ("hardware/nxp/nfc", "platform/hardware/nxp/nfc"),
        ("system/secure_element", "platform/system/secure_element"),
        ("packages/modules/Nfc", "platform/packages/modules/Nfc"),
    ):
        require(owners.get(path) == name,
                f"official Android17 SE/NFC/OMAPI source owner changed: {path}")
    require(LEGACY_PATH not in owners and LEGACY_NAME not in owners.values(),
            "legacy P73 SE HIDL accidentally activated")
    candidate_root = ET.parse(
        root / "aosp17_pe_p2_se_security_candidate.xml").getroot()
    candidate_nodes = list(candidate_root)
    expected_source = {
        "path": "hardware/nxp/secure_element",
        "name": "platform/hardware/nxp/secure_element",
        "remote": "aosp",
        "revision": SEC_SHA,
        "upstream": "refs/tags/android-security-17.0.0_r3",
        "groups": "pdk",
    }
    require(candidate_root.tag == "manifest"
            and len(candidate_nodes) == 3
            and [x.tag for x in candidate_nodes]
                == ["include", "remove-project", "project"]
            and candidate_nodes[0].attrib
                == {"name": "aosp17_pe_p2_kernel_configs.xml"}
            and candidate_nodes[1].attrib
                == {"name": "platform/hardware/nxp/secure_element"}
            and candidate_nodes[2].attrib == expected_source,
            "experimental SE r3 source checkout is not strictly isolated")
    validator = (root / "tools/validate_aosp17_base_profiles.py").read_text()
    tests = (root / "tools/test_aosp17_manifest_entrypoint.py").read_text()
    require(f'if "{LEGACY_PATH}" in projects:' in validator
            and f'"{LEGACY_NAME}"' in validator
            and '"hardware/nxp/secure_element": "platform/hardware/nxp/secure_element"'
                in validator,
            "row 174 archived HAL deny / official owner pin missing")
    for method in ("test_legacy_nxp_p73_hidl_se_cannot_enter_android17",
                   "test_legacy_nxp_p73_cannot_take_official_aosp17_se_hal",
                   "test_legacy_nxp_p73_cannot_take_system_omapi_owner"):
        require(f"def {method}(" in tests,
                "row 174 adversarial regression absent: " + method)
    subprocess.run(
        [sys.executable, str(root / "tools/validate_aosp17_base_profiles.py")],
        cwd=root, check=True)
    print("PASS: 25 source profiles preserve official NXP SE + system OMAPI")
    print("PASS: source manifest guard rejects old SE HIDL and owner takeovers")


def main():
    require(len(sys.argv) == 5,
            "Usage: check_nxp_se_aidl_boundary.py OLD_NXP_SE AOSP17_SE"
            " NXP17_SE MANIFEST")
    legacy, official, vendor, mf = [
        Path(arg).resolve() for arg in sys.argv[1:]
    ]
    require(all(p.is_dir() for p in (legacy, official, vendor, mf)),
            "one or more source checkouts not present")
    legacy_secure_element(legacy)
    base = official_aosp17(official)
    contemporary_nxp(vendor)
    source_delta(official, base, vendor)
    manifest(mf)
    print("PASS: row174 official AOSP17 SE AIDL ownership, not legacy P73 HIDL")
    print("NOT TESTED: SE Soong/NDK, real APDUs, VINTF, SELinux, firmware, mondrian")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, ET.ParseError,
            subprocess.CalledProcessError) as error:
        print("FAIL:", error, file=sys.stderr)
        sys.exit(1)
