#pragma once

/*
 * OAC-owned conservative driver-family policy.  These names are evaluated by
 * both the kernel telemetry path and the user-mode preflight/monitor.  Exact
 * Authenticode SHA-256 denies live in the generated user-mode policy include.
 *
 * A basename rule intentionally denies the whole family in production.  Put
 * version-dependent or commonly legitimate tools in the review list instead.
 */

#define OAC_DRIVER_POLICY_VERSION 0x00010000UL

#define OAC_DRIVER_DENY_BASENAMES_A \
    "asio.sys", "asio2.sys", "asio3.sys", "asio32.sys", "asio64.sys", \
    "asupio64.sys", "aswarpot.sys", "capcom.sys", "dbk64.sys", \
    "dbutil.sys", "dbutil_2_3.sys", "dbutil_2_5.sys", "eneio64.sys", \
    "gdrv.sys", "gdrv2.sys", "glckio2.sys", "inpout32.sys", \
    "inpoutx64.sys", "iqvw64e.sys", "kph.sys", "kprocesshacker.sys", \
    "kprocesshacker2.sys", "kprocesshacker3.sys", "mhyprot2.sys", \
    "mhyprot3.sys", "msio.sys", "msio32.sys", "msio64.sys", \
    "ntiolib.sys", "pcdsrvc_x64.pkms", "rtcore64.sys", "winio32.sys", \
    "winio64.sys", "winring0.sys", "winring0a64.sys", "winring0x64.sys"

#define OAC_DRIVER_DENY_BASENAMES_W \
    L"asio.sys", L"asio2.sys", L"asio3.sys", L"asio32.sys", L"asio64.sys", \
    L"asupio64.sys", L"aswarpot.sys", L"capcom.sys", L"dbk64.sys", \
    L"dbutil.sys", L"dbutil_2_3.sys", L"dbutil_2_5.sys", L"eneio64.sys", \
    L"gdrv.sys", L"gdrv2.sys", L"glckio2.sys", L"inpout32.sys", \
    L"inpoutx64.sys", L"iqvw64e.sys", L"kph.sys", L"kprocesshacker.sys", \
    L"kprocesshacker2.sys", L"kprocesshacker3.sys", L"mhyprot2.sys", \
    L"mhyprot3.sys", L"msio.sys", L"msio32.sys", L"msio64.sys", \
    L"ntiolib.sys", L"pcdsrvc_x64.pkms", L"rtcore64.sys", L"winio32.sys", \
    L"winio64.sys", L"winring0.sys", L"winring0a64.sys", L"winring0x64.sys"

#define OAC_DRIVER_REVIEW_BASENAMES_A \
    "procmon23.sys", "vboxdrv.sys", "vboxsup.sys"

#define OAC_DRIVER_REVIEW_BASENAMES_W \
    L"procmon23.sys", L"vboxdrv.sys", L"vboxsup.sys"
