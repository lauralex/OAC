# Hardware identity review

## Scope and handling

The review used hash-verified copies of first-party Windows drivers in an isolated temporary
directory. No live system binary was opened in place, patched, or loaded. Each IDALib database was
saved beside its copy. The implementation uses the public storage, SetupAPI, firmware, network,
HID, Bluetooth, and mount-manager interfaces confirmed by the review; it does not call private
driver IOCTLs or reproduce private Windows algorithms.

The reviewed machine was Windows build 22621 with components serviced to different patch
revisions. These findings guide which documented interfaces to query, not hardcoded offsets or
signatures. Runtime collection is therefore build-independent and treats unavailable newer
properties as missing evidence.

## Main findings translated into collectors

- `disk.sys` accepts the legacy read-only ATA IDENTIFY path used by
  `SMART_RCV_DRIVE_DATA`. OAC uses it only as an independent compatibility source and validates
  the returned 512-byte identify block.
- `stornvme.sys` forms standard serial-number and device-identifier responses from controller and
  namespace Identify data. OAC cross-checks `StorageDeviceProperty` and
  `StorageDeviceIdProperty` against bounded protocol-specific controller SN/FGUID and namespace
  NGUID/EUI64 queries.
- `storport.sys` implements `StorageAdapterSerialNumberProperty`, `StorageFruIdProperty`, device
  IDs, DUIDs, and protocol-specific Identify queries. OAC queries each property independently and
  validates every version, size, offset, count, and variable-length field.
- `classpnp.sys` builds a DUID from device IDs, device descriptors, and drive-layout identity.
  OAC therefore treats `StorageDeviceUniqueIdProperty` as a separate strong correlation source
  rather than inventing its own equivalent.
- `USBSTOR.sys` obtains storage serials from SCSI VPD page 0x80 with a USB string-descriptor
  fallback. Standard storage descriptors and the PnP instance/container views cover those paths.
- `mountmgr.sys`, `partmgr.sys`, `volmgr.sys`, and `volmgrx.sys` expose unique IDs, stable GUIDs,
  GPT disk/partition GUIDs, MBR signatures, and dynamic-volume identities. OAC uses documented
  volume, mount-device, and drive-layout queries.
- `spaceport.sys` derives stable Storage Spaces identity from `STORAGE_IDENTIFIER` data. OAC keeps
  the underlying storage identifiers as typed evidence and does not depend on its private hash
  construction.
- `usbhub3.sys` validates serial descriptors, compares them on re-enumeration, and builds PnP
  container identity from device descriptors and valid serial inputs. OAC correlates the public
  PnP instance/container/location properties with USB/storage identities.
- `ndis.sys` persists both current and permanent physical addresses. OAC obtains both through
  `MIB_IF_ROW2`, limits primary anchors to hardware interfaces, and reports mismatches as evidence
  because Wi-Fi randomization and administrative overrides can be legitimate.
- `monitor.sys` and `dxgkrnl.sys` consume EDID and DisplayID identity. OAC parses the EDID numeric
  and text serial fields, hashes the complete descriptor (which also covers DisplayID extensions),
  and reports EDID override keys.
- `ACPI.sys` exposes device `_UID` data through normal PnP identity. `pci.sys` processes the PCIe
  Device Serial Number capability, but the review did not identify a safe universal user-mode
  interface for raw PCI configuration access. OAC therefore uses PnP/container/topology evidence
  and never issues undocumented PCI config-space requests.
- `tpm.sys` implements TPM command transport but no generic machine serial. OAC does not mislabel
  mutable TPM keys or firmware versions as a serial. `Wdf01000.sys` is property plumbing, not a
  separate identity source. `BTHUSB.sys` likewise exposes no trustworthy private radio serial, so
  OAC uses the supported Bluetooth radio and PnP APIs.
- `CmBatt.sys` and `battc.sys` confirmed the documented battery-class query path for device name,
  manufacturer, manufacture date, unique ID, and serial number. OAC now queries those bounded
  values through `IOCTL_BATTERY_QUERY_TAG`/`IOCTL_BATTERY_QUERY_INFORMATION`; replaceable batteries
  remain peripheral-only evidence and never churn the core token.
- `hidclass.sys` and `hidusb.sys` confirmed that HID serial retrieval is backed by the class/minidriver
  descriptor path. OAC keeps using `HidD_GetSerialNumberString`; it does not issue private USB URBs.
- `BTHPORT.sys` maintains local/remote addresses and BR/LE container identity, including address
  randomization and reconciliation. OAC uses the supported radio and remembered-device APIs and
  treats every remote address as weak peripheral evidence because LE addresses can rotate.
- `mssmbios.sys` builds several version-5 GUID hardware IDs from different SMBIOS field combinations
  and persists both `ComputerHardwareId` and `ComputerHardwareIds`. OAC reads those public registry
  results as corroboration and also parses the underlying SMBIOS fields, but deliberately does not
  clone the private Windows GUID-generation algorithm.
- `UcmCx.sys` exposes connector IDs and cable capabilities, not a stable machine serial.
  `WpdUpFltr.sys` is portable-device request plumbing and likewise adds no trustworthy independent
  identity. Neither justifies a private IOCTL dependency.

## Reviewed copy inventory

| File | File version | SHA-256 |
|---|---|---|
| ACPI.sys | 10.0.22621.5415 | `CF700C944C5FAAEC7B8CD82B4D857A085E027678C2C292F1B954EA5CA0222738` |
| BTHUSB.sys | 10.0.22621.7376 | `9B77EB970EBCC7D73FBC5412476DB3FB68C1259C70333432BE02FB1C74E2903F` |
| BTHPORT.sys | 10.0.22621.1 | `6F8251CE385D1161E571DA52D8D05A64D5134D2905BF1298C83C3F37E39F209B` |
| battc.sys | 10.0.22621.1 | `0291EAF64ABD2A47B58DA941E27E5259BCD327D65944859090B114DAD5A17385` |
| classpnp.sys | 10.0.22621.5983 | `589753BD9FD147339D72B95F1D308EDDBA001D2616DF0B6B9042D70C22187BC3` |
| CmBatt.sys | 10.0.22621.1 | `E2142D8866432241258B9F73D16A208939B6D9B762AAAF60B89E037BA3B59558` |
| disk.sys | 10.0.22621.5415 | `2070BC649F102ED588BF9A0262747B9516D92E83AD62BFE9EC92B8EAF088C219` |
| dxgkrnl.sys | 10.0.22621.7376 | `9013C5766B2210E3F99DB6BA69060AFD6A6436EB78951C395829562D1EE8DC1A` |
| hidclass.sys | 10.0.22621.1 | `B04A5023700AF14207C982B5568FF7FB2500032E9422571C340A0A6C36501AAB` |
| hidusb.sys | 10.0.22621.7376 | `889CD06087D8142F34DEAA92E3DF6D3B160E8FD466756C2A8A8AA6848EBC691F` |
| monitor.sys | 10.0.22621.5415 | `CA1F9C6FD45BB965C51899B8225DD8B2225D4212ADF34F866D94305CA3CE44F7` |
| mountmgr.sys | 10.0.22621.2506 | `ED2F33258083916BA21BC4E1B23C889E87AA12ED290DB8DB9CFB6084A8577C50` |
| mssmbios.sys | 10.0.22621.1 | `76E79D2B988691474B2289A3B961188E8F52CB6A4667A4E7B762C00C2FA57D1B` |
| ndis.sys | 10.0.22621.7376 | `BF7E1C3D612149C71109DC0C2AD319384E76B3A4728ACEA38698A0DEB559DF38` |
| netio.sys | 10.0.22621.7376 | `9830B38D2D2D91EA99B611980082E57686A007FFDC296814A05DB51EEEB6778C` |
| partmgr.sys | 10.0.22621.2506 | `19E563D24A84BA9928C7C2C4D4A9ADD59C79D0F5CDA640E0BF98DFCC4736BDA6` |
| pci.sys | 10.0.22621.5697 | `4048A6BE89BF74E77154A4963CE6D085B2A75B6B9AAA3A75DC8761B1F77F4BE5` |
| spaceport.sys | 10.0.22621.7376 | `CD4A40006D55E6D4AFD46B767CA9A399FDFE99DF6D39004E44EDC5F0F68FEA3E` |
| stornvme.sys | 10.0.22621.6274 | `8FA7D4A03E492AF3E76F27DC317BAAB6388657CC67F16D4AAFCDE9EB37AD0A09` |
| storport.sys | 10.0.22621.7079 | `E28B3D8304258CCB2FA5E240A57CE02F2E9EFFFDE9361208CA326C6DDBFC955F` |
| tcpip.sys | 10.0.22621.7376 | `F6672EDFDF8CDDAF660D6EAFFF35EBCD866EB70E6B975F9890F3FABE82FD2BCD` |
| tpm.sys | 10.0.22621.7219 | `BC6034CF556D7350A0F5AE3434F95E00737983143A3BD7601C19EFD2E966E76E` |
| usbhub3.sys | 10.0.22621.7376 | `6CEF634FE4923ADB32494575D270AEB6C0961BAAA88F8DC9AE05E8A3A1BD0A36` |
| USBSTOR.sys | 10.0.22621.5415 | `798E3F7D8361B3E2D8FC986D369866086BE2103572F64B92854631B7B5405AEF` |
| USBXHCI.sys | 10.0.22621.7376 | `9441CE6C2A60A1682BC7D17961E0D8BB3BAB8ADE4951279940A070C6B66A448C` |
| UcmCx.sys | 10.0.22621.5983 | `2B46DC41E892F361BCB96055DB96AC3015F358F6A1B778E66A9DD927DB417515` |
| volmgr.sys | 10.0.22621.2506 | `79B9C77D412F7A5A7475D531F2427DED44606A510EFDF8985986F76E6A2AB214` |
| volmgrx.sys | 10.0.22621.7079 | `DFF55F90254D5741E57CFB60BF4E1D602C8DF55B93E4BF1DC95748EFAEB3E382` |
| Wdf01000.sys | 1.33.22621.5415 | `F09F84A0D58B3F407950888DFC5627A8FFED2FA9D6D9AA66AE1DBB068AEF5418` |
| WpdUpFltr.sys | 10.0.22621.1 | `ABE2808BA33947696486EA5EECADFFEA731E51B996CD62A3CA0426EE2A0FF888` |

The source and safe-copy SHA-256 values were compared before analysis. All 30 entries had a saved
`.i64` database after the review.

## Security and privacy interpretation

The collector distinguishes strong, medium, weak, contextual, and removable/peripheral evidence.
It rejects common OEM placeholders, all-zero/all-`FF` fields, malformed lengths, and duplicates.
Independent sources with the same semantic group are checked for agreement. A disagreement is an
anomaly, not an automatic cheating verdict.

Raw component values live only in the scanner process, are best-effort zeroed after use, and are
not written to reports. The primary token is a versioned SHA-256 composite over sorted hashes of
stable core anchors. Removable disks/volumes, USB, HID, Bluetooth, batteries, and monitors remain
available for evidence correlation but do not churn the core token. A production service that
needs fuzzy recurring-device matching should compute server-keyed component tokens inside an
authenticated protocol; embedding a reusable secret in the client would not provide that
property.
