# Carry-over Benchmark v2.6 — Fresh Corpus Refresh

- corpus_target: **1123**
- resolved_rows: **1123**
- success / partial / fatal: **1110 / 4 / 9**

> This is a baseline refresh, not a proof-of-value report. Pair-labeled recall/FP and tier ROC remain follow-on evaluation lanes.

## Success quality

- nonzero findings: **1110 / 1110**
- nonzero CVE: **1089 / 1110**
- actionable candidates > 0: **1094 / 1110**
- digest verifier pass: **1110 / 1110**
- report verifier pass: **1038 / 1110**

## Extraction / inventory breakdown

| metric | count |
|---|---:|
| extraction:ok | 1110 |
| extraction:missing | 9 |
| extraction:partial | 4 |
| inventory:sufficient | 1110 |
| inventory:missing | 9 |
| inventory:insufficient | 4 |

## Vendor breakdown

| vendor | success | partial | fatal | error |
|---|---:|---:|---:|---:|
| asus | 105 | 0 | 2 | 0 |
| belkin | 37 | 0 | 0 | 0 |
| dlink | 262 | 0 | 0 | 0 |
| linksys | 55 | 0 | 0 | 0 |
| netgear | 375 | 0 | 0 | 0 |
| tplink | 146 | 2 | 0 | 0 |
| trendnet | 110 | 2 | 7 | 0 |
| zyxel | 20 | 0 | 0 | 0 |

## Holdouts

| vendor | firmware | status | extraction | inventory | analyst_reasons |
|---|---|---|---|---|---|
| asus | FW_RT_N10_1024.zip | fatal | missing | missing | assessment_unavailable |
| asus | FW_WL_330gE_2020.zip | fatal | missing | missing | assessment_unavailable |
| tplink | RE400_V1_170111.zip | partial | partial | insufficient | - |
| tplink | TL-WA801ND_US__V5_170905.zip | partial | partial | insufficient | - |
| trendnet | TEG-082WS_1.00.010.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TEG-204WS_1.00.010.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TEG-284WS_1.00.010.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TEG-40128_1.00.015.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TEW-410APBplus_0.0.0.zip | partial | partial | insufficient | - |
| trendnet | TEW-411BRPplus_2.07.zip | partial | partial | insufficient | - |
| trendnet | TFC-1600MM_2.03.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TPE-1620WS_1.00.010.zip | fatal | missing | missing | assessment_unavailable |
| trendnet | TPE-5028WS_0.0.0.zip | fatal | missing | missing | assessment_unavailable |

## Bookkeeping anomalies

- excluded_out_of_corpus: 1
- normalized_alias: 1
