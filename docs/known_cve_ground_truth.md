# Known CVE Ground Truth for SCOUT Validation

Generated: 2026-03-29
Dataset: FirmAE benchmark (`aiedge-inputs/firmae-benchmark/`)
Methodology: CVE affected version ranges cross-referenced against actual filenames in each vendor directory.

---

## Priority 1 — Command Injection (SCOUT taint analysis 탐지 대상)

| CVE | Vendor | Model | Firmware File | Vulnerable? | Binary / Entry Point | Sink | CVSS |
|-----|--------|-------|---------------|-------------|----------------------|------|------|
| CVE-2016-6277 | NETGEAR | R7000 | `R7000-V1.0.3.56_1.1.25.zip` | YES (< 1.0.4.28) | `cgi-bin/` CGI handler | `system()` / `popen()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7000 | `R7000-V1.0.3.60_1.1.27.zip` | YES (< 1.0.4.28) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7000 | `R7000-V1.0.3.68_1.1.31.zip` | YES (< 1.0.4.28) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7000 | `R7000-_V1.0.3.80-1.1.38.zip` | YES (< 1.0.4.28) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7000 | `R7000-V1.0.4.28_1.1.64.zip` | PATCHED (= 1.0.4.28) | — | — | 8.8 |
| CVE-2016-6277 | NETGEAR | R6250 | `R6250-V1.0.0.62_1.0.62.zip` | YES (< 1.0.3.12) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6250 | `R6250-V1.0.0.70_1.0.70.zip` | YES (< 1.0.3.12) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6250 | `R6250-V1.0.0.72_1.0.71.zip` | YES (< 1.0.3.12) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6250 | `R6250_V1.0.1.84-1.0.78.zip` | YES (< 1.0.3.12) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.0.14_1.0.8.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.0.20_1.0.11.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.0.24_1.0.13.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.0.26_1.0.14.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.1.12_1.0.11.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.1.18_1.0.15.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.1.20_1.0.16.zip` | YES (< 1.0.1.22) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6400 | `R6400-V1.0.1.22_1.0.17.zip` | PATCHED (= 1.0.1.22) | — | — | 8.8 |
| CVE-2016-6277 | NETGEAR | R6700 | `R6700-V1.0.0.2_1.0.1.zip` | YES (< 1.0.1.14) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6700 | `R6700-V1.0.0.24_10.0.18.zip` | YES (< 1.0.1.14) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6700 | `R6700-V1.0.0.26_10.0.26.zip` | YES (< 1.0.1.14) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R6900 | `R6900-V1.0.1.48_10.0.30.zip` | LIKELY PATCHED | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7300 | `R7300-V1.0.0.68_1.0.24.zip` | YES (= 1.0.0.68 = fix boundary) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7900 | `R7900-V1.0.0.2_10.0.1.zip` | YES (< 1.0.0.10) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7900 | `R7900-V1.0.0.6_10.0.4.zip` | YES (< 1.0.0.10) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R7900 | `R7900-V1.0.0.8_10.0.5.zip` | YES (< 1.0.0.10) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.68_1.0.27.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.74_1.0.31.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.76_1.0.32.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.90_1.0.39.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.100_1.0.44.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.0.102_1.0.45.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2016-6277 | NETGEAR | R8000 | `R8000-V1.0.2.46_1.0.97.zip` | YES (< 1.0.3.26) | `cgi-bin/` CGI handler | `system()` | 8.8 |
| CVE-2018-6530 | D-Link | DIR-880L | `DIR-880L_REVA_FIRMWARE_PATCH_1.08B04_WW.ZIP` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-880L | `DIR-880L_REVA_FIRMWARE_PATCH_v1.08B06_BETA.zip` | LIKELY PATCHED | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-868L | `DIR-868L_REVA_FIRMWARE_PATCH_v1.20B01_BETA.zip` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-868L | `DIR-868L_REVB_FIRMWARE_PATCH_2.05B02.zip` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-865L | `DIR-865L_REVA_FIRMWARE_PATCH_v1.10B01_BETA.zip` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-860L | `DIR-860L_REVA_FIRMWARE_PATCH_v1.11B01_BETA.zip` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2018-6530 | D-Link | DIR-860L | `DIR-860L_REVB_FIRMWARE_2.03.B03.ZIP` | YES | `soap.cgi` | `system()` | 9.8 |
| CVE-2019-16920 | D-Link | DIR-655 | `DIR-655_REVC_FIRMWARE_3.02.B05.ZIP` | YES | `apply_sec.cgi` | `system()` | 9.8 |
| CVE-2019-16920 | D-Link | DIR-866L | `DIR-866L_REVA_FIRMWARE_v1.03B04.zip` | YES | `apply_sec.cgi` | `system()` | 9.8 |
| CVE-2018-14714 | ASUS | RT-AC3200 | `FW_RT_AC3200_300438250624.ZIP` | YES (bundle ver ≤ 3.0.0.4.380.8024) | `appGet.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E4200 | `FW_E4200_1.0.06.003_US_20140520_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E3200 | `FW_E3200_1.0.05.002_US_20140516_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E3000 | `FW_E3000_1.0.06.002_US_20140409_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E2500 | `FW_E2500_2.0.00.001_US_20140417.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E2100L | `FW_E2100L_1.0.05.004_20120308_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E1550 | `FW_E1550_1.0.03.002_US_20120201_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E1500 | `FW_E1500_v1.0.06.001_US_20140327_code.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E1200 | `FW_E1000_2.1.03.005_US_20140321.bin` | POSSIBLY (E1200 not present; E1000 confirmed) | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2025-34037 (TheMoon) | Linksys | E900 | `FW_E900_1.0.08.002_US_20171208.bin` | YES | `tmUnblock.cgi` | `system()` | 9.8 |
| CVE-2020-10882 | TP-Link | Archer A7 v5 | `Archer_A7_US__V5_180424.zip` | YES | `tdpServer` | `system()` | 8.8 |
| CVE-2014-8888 | D-Link | DIR-815 | `DIR-815_REVA_FIRMWARE_1.04.B03.ZIP` | YES | `hedwig.cgi` / admin handler | `system()` | 9.8 |
| CVE-2014-8888 | D-Link | DIR-815 | `DIR-815_REVB_FIRMWARE_PATCH_2.07.B01.ZIP` | LIKELY PATCHED | — | — | 9.8 |
| CVE-2014-8888 | D-Link | DIR-815A1 | `DIR-815A1_FW101SSB05.bin` | YES | `hedwig.cgi` / admin handler | `system()` | 9.8 |
| CVE-2014-0356 | Zyxel | NBG-419N | `NBG-419N_1.00_BFQ.7_C0.zip` | YES | `management.c` CGI | `system()` | 8.8 |

---

## Priority 2 — Buffer Overflow (SCOUT pattern scan 탐지 대상)

| CVE | Vendor | Model | Firmware File | Vulnerable? | Binary | Overflow Type | CVSS |
|-----|--------|-------|---------------|-------------|--------|---------------|------|
| CVE-2020-15636 | NETGEAR | R6400v2 | `R6400v2-V1.0.2.60_10.0.44.zip` | LIKELY YES | `check_ra` daemon | Stack BOF | 8.8 |
| CVE-2020-15636 | NETGEAR | R6700v3 | `R6700v3-V1.0.2.60_10.0.44.zip` | LIKELY YES | `check_ra` daemon | Stack BOF | 8.8 |
| CVE-2020-15636 | NETGEAR | R7000P | `R7000P-V1.3.1.44_10.1.23.zip` | LIKELY YES | `check_ra` daemon | Stack BOF | 8.8 |
| CVE-2020-15636 | NETGEAR | R6900P | `R6900P-V1.3.1.44_10.1.23.zip` | LIKELY YES | `check_ra` daemon | Stack BOF | 8.8 |
| CVE-2020-15636 | NETGEAR | R8000 | `R8000-V1.0.0.110_1.0.70.zip` | LIKELY YES | `check_ra` daemon | Stack BOF | 8.8 |
| CVE-2017-6548 | ASUS | RT-N56U | `FW_RT_N56U_30043807378.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-N56U B1 | `FW_RT_N56U_B1_30043785291.zip` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-N66U | `FW_RT_N66U_300438250702.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-N66U C1 | `FW_RT_N66U_C1_300438432738.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-AC66U | `FW_RT_AC66U_300438250470.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-AC66U B1 | `FW_RT_AC66U_B1_300438432738.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-AC68U | `FW_RT_AC68U_300438432738.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-6548 | ASUS | RT-AC68UF | `FW_RT_AC68UF_300438432738.ZIP` | YES | `networkmap` | Stack BOF | 9.8 |
| CVE-2017-13772 | TP-Link | WR940N v3 | `TL-WR940N_US__V3_161107_1479957675241p.zip` | YES | `httpd` (`PingIframeRpm.htm`) | Stack BOF | 8.8 |
| CVE-2017-13772 | TP-Link | WR940N v4 | `TL-WR940N_US__V4_160617_1476690524248q.zip` | YES | `httpd` (`PingIframeRpm.htm`) | Stack BOF | 8.8 |
| CVE-2017-13772 | TP-Link | WR940N v5 | `TL-WR940N_US__V5_170912.zip` | YES | `httpd` (`PingIframeRpm.htm`) | Stack BOF | 8.8 |
| CVE-2017-13772 | TP-Link | WR940N v6 | `TL-WR940N_US__V6_171030.zip` | POSSIBLY (verify) | `httpd` | Stack BOF | 8.8 |
| CVE-2019-11418 | TRENDnet | TEW-632BRP | `TEW-632BRP_1.010B32.zip` | YES | `apply.cgi` HNAP handler | Stack BOF | 9.8 |
| CVE-2022-33007 | TRENDnet | TEW-751DR | `TEW-751DR_v1.03B03.zip` | YES | `genacgi_main` | Stack BOF | 9.8 |
| CVE-2022-33007 | TRENDnet | TEW-752DRU | `TEW-752DRU_v1.03B01.zip` | YES | `genacgi_main` | Stack BOF | 9.8 |
| CVE-2014-1635 | Belkin | N750 F9K1103 | `F9K1103_WW_1.10.23.bin` | YES | `login.cgi` | Stack BOF | 9.8 |

---

## Priority 3 — Auth Bypass / Hardcoded Credentials

| CVE | Vendor | Model | Firmware File | Vulnerable? | Binary / Mechanism | CVSS |
|-----|--------|-------|---------------|-------------|-------------------|------|
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.0.28_1.0.15.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.0.42_1.0.23.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.0.52_1.0.26.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.0.56_1.0.28.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.2.100_1.0.82.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.2.116_1.0.90.zip` | YES (< 1.0.2.122) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R8500 | `R8500-V1.0.2.122_1.0.94.zip` | PATCHED (= 1.0.2.122) | — | 9.8 |
| CVE-2017-5521 | NETGEAR | R8300 | `R8300-V1.0.2.122_1.0.94.zip` | PATCHED (= 1.0.2.122) | — | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.3.56_1.1.25.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.3.60_1.1.27.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.3.68_1.1.31.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-_V1.0.3.80-1.1.38.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000_V1.0.4.18_1.1.52.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.4.28_1.1.64.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000_V1.0.4.30_1.1.67.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.5.64_1.1.88.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.5.70_1.1.91.zip` | YES (< 1.0.7.2) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R7000 | `R7000-V1.0.7.2_1.1.93.zip` | PATCHED (= 1.0.7.2) | — | 9.8 |
| CVE-2017-5521 | NETGEAR | R6400 | `R6400-V1.0.0.14_1.0.8.zip` | YES (< 1.0.1.44) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R6400 | `R6400-V1.0.0.20_1.0.11.zip` | YES (< 1.0.1.44) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R6400 | `R6400-V1.0.1.24_1.0.18.zip` | YES (< 1.0.1.44) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | R6400 | `R6400-V1.0.1.44_1.0.31.zip` | PATCHED (= 1.0.1.44) | — | 9.8 |
| CVE-2017-5521 | NETGEAR | WNDR3400v3 | `WNDR3400v3-V1.0.0.20_1.0.28.zip` | YES (< 1.0.1.18) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | WNDR3400v3 | `WNDR3400v3-V1.0.0.38_1.0.40.zip` | YES (< 1.0.1.18) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | WNDR3400v3 | `WNDR3400v3-V1.0.1.12_1.0.58.zip` | YES (< 1.0.1.18) | `passwordrecovered.cgi` auth bypass | 9.8 |
| CVE-2017-5521 | NETGEAR | WNDR3400v3 | `WNDR3400v3-V1.0.1.18_1.0.63.zip` | PATCHED (= 1.0.1.18) | — | 9.8 |
| CVE-2014-8244 | Linksys | EA2700 | `FW_EA2700_1.1.40.166516_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA4500 v3 | `FW_EA4500V3_3.1.6.172023_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA4500 v3 | `FW_EA4500V3_3.1.7.181919_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6200 | `FW_EA6200_1.1.41.188556_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6400 | `FW_EA6400_1.1.40.176337_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6400 | `FW_EA6400_1.1.40.184085_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6700 | `FW_EA6700_1.1.40.176451_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6700 | `FW_EA6700_1.1.41.183873_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-8244 | Linksys | EA6900 | `FW_EA6900_1.1.43.182871_prod.img` | YES | JNAP protocol handler | 9.8 |
| CVE-2014-9583 | ASUS | RT-AC56U | `FW_RT_AC56U_300438250624.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-9583 | ASUS | RT-AC66U | `FW_RT_AC66U_300438250470.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-9583 | ASUS | RT-AC68U | `FW_RT_AC68U_300438432738.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-9583 | ASUS | RT-AC87U | `FW_RT_AC87U_300438250702.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-9583 | ASUS | RT-N56U | `FW_RT_N56U_30043807378.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-9583 | ASUS | RT-N66U | `FW_RT_N66U_300438250702.ZIP` | YES | `infosvr` RCE | 9.8 |
| CVE-2014-0354 | Zyxel | NBG-419N | `NBG-419N_1.00_BFQ.7_C0.zip` | YES | Hardcoded credential `qweasdzxc` | 8.8 |
| CVE-2014-0354 | Zyxel | NBG-419N v2 | `NBG-419N_v2_V1.00_AACU.7_C0.zip` | POSSIBLY YES | Hardcoded credential | 8.8 |

---

## Summary: Confirmed Validation Targets (Prioritized)

### Tier A — High-Confidence Vulnerable (use for TP validation first)

| Priority | CVE | Firmware File | SCOUT Detection Target |
|----------|-----|---------------|----------------------|
| A1 | CVE-2016-6277 | `R7000-V1.0.3.56_1.1.25.zip` | taint: HTTP param → `system()` in cgi-bin |
| A2 | CVE-2018-6530 | `DIR-880L_REVA_FIRMWARE_PATCH_1.08B04_WW.ZIP` | taint: SOAP body → `system()` in `soap.cgi` |
| A3 | CVE-2019-16920 | `DIR-655_REVC_FIRMWARE_3.02.B05.ZIP` | taint: POST param → `system()` in `apply_sec.cgi` |
| A4 | CVE-2025-34037 | `FW_E4200_1.0.06.003_US_20140520_code.bin` | taint: HTTP param → `system()` in `tmUnblock.cgi` |
| A5 | CVE-2020-10882 | `Archer_A7_US__V5_180424.zip` | taint: UDP packet → `system()` in `tdpServer` |
| A6 | CVE-2022-33007 | `TEW-751DR_v1.03B03.zip` | BOF: `strcpy`/`sprintf` in `genacgi_main` |
| A7 | CVE-2017-5521 | `R8500-V1.0.0.28_1.0.15.zip` | auth bypass: `passwordrecovered.cgi` no auth check |
| A8 | CVE-2014-0354 | `NBG-419N_1.00_BFQ.7_C0.zip` | hardcoded cred: `qweasdzxc` in binary strings |
| A9 | CVE-2014-9583 | `FW_RT_N66U_300438250702.ZIP` | taint: `infosvr` packet → `system()` |
| A10 | CVE-2014-1635 | `F9K1103_WW_1.10.23.bin` | BOF: `login.cgi` `strcpy` |

### Tier B — Use for Patch-Comparison (confirmed patched counterparts)

| CVE | Vulnerable File | Patched File |
|-----|----------------|-------------|
| CVE-2016-6277 | `R7000-_V1.0.3.80-1.1.38.zip` | `R7000-V1.0.4.28_1.1.64.zip` |
| CVE-2017-5521 | `R8500-V1.0.2.116_1.0.90.zip` | `R8500-V1.0.2.122_1.0.94.zip` |
| CVE-2017-5521 | `R7000-V1.0.5.70_1.1.91.zip` | `R7000-V1.0.7.2_1.1.93.zip` |
| CVE-2017-5521 | `WNDR3400v3-V1.0.1.12_1.0.58.zip` | `WNDR3400v3-V1.0.1.18_1.0.63.zip` |
| CVE-2016-6277 | `R6400-V1.0.1.20_1.0.16.zip` | `R6400-V1.0.1.22_1.0.17.zip` |

---

## Validation Plan

### Phase 1: True Positive Rate (Tier A targets)

For each Tier A firmware:
1. Run: `./scout analyze <firmware_file> --no-llm --stages tooling,extraction,structure,carving,firmware_profile,inventory,enhanced_source,taint_propagation`
2. Check `stages/taint_propagation/stage.json` for findings referencing the expected binary + sink
3. Record: TP if CVE binary + sink pattern found, FN if not

### Phase 2: Patch-diff Validation (Tier B pairs)

Run SCOUT on both vulnerable and patched firmware from same model/CVE pair:
- Vulnerable firmware should produce a finding
- Patched firmware should NOT produce the same finding
- Confirms SCOUT tracks actual code changes, not just model presence

### Phase 3: False Positive Rate

Run SCOUT on 5 randomly selected firmware NOT in this list:
- Record any findings from `taint_propagation` or BOF patterns
- Any matching the CVE-specific binaries (`tmUnblock.cgi`, `soap.cgi`, `apply_sec.cgi`, etc.) = FP

### Scoring

```
True Positive Rate  = TP / (TP + FN)         # target: >= 0.70
False Positive Rate = FP / (FP + TN)         # target: <= 0.20
Precision           = TP / (TP + FP)
F1                  = 2 * (P * R) / (P + R)
```

### Expected SCOUT Stage Coverage per CVE Type

| CVE Type | Primary Stage | Secondary Stage | Signal |
|----------|--------------|----------------|--------|
| Command injection | `taint_propagation` | `enhanced_source` | INPUT_API → `system()`/`popen()` path |
| Buffer overflow | `inventory` (BOF patterns) | `fp_verification` | `strcpy`/`sprintf` without bounds |
| Auth bypass | `inventory` (credential scan) | `semantic_classification` | hardcoded strings / missing auth check |
| RCE via service | `taint_propagation` | `surfaces` | network socket → sink |

### Notes on Dataset Gaps

- **NETGEAR R6250**: CVE-2016-6277 fix boundary is 1.0.3.12; files `V1.0.3.6` and `V1.0.3.12` are present — use as patch-diff pair
- **D-Link DIR-815**: RevA is vulnerable, RevB patch (2.07.B01) may already be patched — verify with binary diff
- **ASUS RT-AC3200**: CVE-2018-14714 only one firmware present — cannot do patch-diff, TP-only test
- **Linksys EA6500**: `FW_EA6500_1.1.29.162351_prod.SSA` — `.SSA` extension (encrypted/signed), may not extract cleanly
- **TRENDnet TEW-632BRP**: CVE-2019-11418 — only one version present, no patch-diff possible
- **Zyxel NBG-419N**: Both CVE-2014-0354 (hardcoded cred) and CVE-2014-0356 (cmd injection) affect same file `NBG-419N_1.00_BFQ.7_C0.zip` — one run tests both
