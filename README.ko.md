<p align="right">
  <a href="README.md">English</a> |
  <strong>한국어</strong>
</p>

# SCOUT (v3.0.0-rc1)

### 결정론적 증거 계보를 갖춘 AEG-First 펌웨어 익스플로잇 가능성 플랫폼

**SCOUT은 가공되지 않은 펌웨어 바이너리를 증거 기반 익스플로잇 가능성 체인, 실험실 한정 Proof-of-Vulnerability 모듈, 내부 레드팀용 controlled weaponization package, 감사 가능한 보고서로 변환하는 AEG-first 펌웨어 분석 플랫폼입니다. 이제 바이너리와 쉘 스크립트를 동시에 감사하는 하이브리드 분석 엔진을 탑재했습니다.**

*기존의 스캐너들이 탐지 수량과 속도에만 치중할 때, SCOUT은 제품보안/내부 레드팀을 위한 고신뢰도 AEG 코파일럿 역할을 수행합니다. 단순한 CVE 목록을 나열하는 대신, ELF 바이너리와 쉘 스크립트를 가로지르는 익스플로잇 체인을 재구성하고, 증거 기반 추론과 실험실 한정 PoV/PoC 검증을 거쳐 private·scope-bound weaponization으로 승격할 수 있게 합니다.*

<br />

<div align="center">
  <a href="#what-you-can-do">주요 기능</a> •
  <a href="#why-scout">SCOUT의 강점</a> •
  <a href="#quick-start">빠른 시작</a> •
  <a href="#key-features">핵심 특징</a> •
  <a href="CHANGELOG.md">변경 이력</a>
</div>

<br />

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero_(stdlib)-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-3.0.0--rc1-red?style=for-the-badge)]()

[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blue?style=for-the-badge&logo=github)]()
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.6+VEX-brightgreen?style=for-the-badge)]()
[![SLSA](https://img.shields.io/badge/SLSA-Level_2-purple?style=for-the-badge)]()

<br />

<table>
<tr>
<td align="center"><strong>1,123</strong><br/><sub>분석 대상 펌웨어</sub></td>
<td align="center"><strong>98.8%</strong><br/><sub>분석 성공률</sub></td>
<td align="center"><strong>1,300+</strong><br/><sub>스크립트 전수 조사</sub></td>
<td align="center"><strong>99.3%</strong><br/><sub>오탐 감소율 (LLM)</sub></td>
<td align="center"><strong>v3.0.0-rc1</strong><br/><sub>하이브리드 엔진</sub></td>
</tr>
</table>

</div>

---

<h2 id="what-you-can-do">🚀 SCOUT으로 할 수 있는 것</h2>

- **하이브리드 분석**: 단일 파이프라인에서 ELF 바이너리와 쉘 스크립트를 통합적으로 감사합니다.
- **심층 익스플로잇 탐지**: `Web -> IPC -> Config -> Daemon` 또는 `Shell -> Binary`로 이어지는 복합 공격 체인을 탐지합니다.
- **AEG-first AutoPoC**: **Exploit Pattern RAG**를 활용하여 펌웨어 증거에서 실험실 검증용 Proof-of-Vulnerability 모듈을 생성합니다.
  - SCOUT은 firmware-relevant CVE seed를 위해 PoC-in-GitHub 메타데이터 전용 importer와 human-review-required draft pattern-card promoter를 포함합니다.
  - PoC-in-GitHub는 귀중한 upstream seed로 사용하되, SCOUT은 raw 공개 PoC 저장소를 clone/실행/prompt 주입하지 않습니다. 사람이 검토한 pattern card만 AutoPoC retrieval 대상이 됩니다.
  - 플랫폼 수준 AEG claim은 [`docs/aeg_e2e_validation.md`](docs/aeg_e2e_validation.md)의 동적 증거/FP gate를 통과해야 합니다. 자세한 내용은 [`docs/exploit-pattern-rag.md`](docs/exploit-pattern-rag.md)를 참고하세요.
  - 내부 레드팀 활용에서 weaponization은 공개 payload 배포가 아니라 **허가된 범위의 controlled promotion layer**입니다. 대상 scope, firmware hash, precondition, 재현성, cleanup, evidence ledger를 묶는 설계는 [`docs/controlled_weaponization_layer.md`](docs/controlled_weaponization_layer.md)에 정리합니다.
- **증거 기반 조사**: 글래스모피즘 웹 대시보드를 통해 디컴파일된 P-code와 쉘 로직을 시각적으로 조사합니다.
- **Controlled Weaponization 준비도**: 검증된 PoV evidence를 내부 레드팀이 사용할 private·scope-bound exploit package로 승격할 수 있게 설계합니다.
- **감사/규제 대응형 보고**: SARIF, CycloneDX 1.6 SBOM+VEX, SLSA L2 증명서를 생성합니다.

---

<h2 id="aeg-rag-status">🧪 현재 AEG / Exploit RAG 검증 상태</h2>

SCOUT v3.0.0-rc1의 1순위는 감사 리포팅이 아니라 **AEG(Automated Exploit Generation) 품질**입니다. 따라서 RAG 확장은 "공개 PoC를 많이 넣었다"가 아니라, 펌웨어 증거에서 재현 가능한 PoV를 만들고 patched/control에서 fail-closed 되는지로 판단합니다.

| 항목 | 현재 상태 |
|---|---|
| 공개 RAG card | `memory_stateful_probe`, `cgi_param_cmd_injection`, `config_derived_cmd_injection`, `netgear_passwordrecovered_auth_bypass` |
| Synthetic vulnerable/control pair | 3개 card 모두 통과 |
| Real known-vulnerable/patched firmware pair | 1개 — Netgear R7000 CVE-2017-5521 stable pair proof 기록됨 |
| 공식 펌웨어 pair 확보 | NETGEAR R7000(CVE-2017-5521), D-Link DIR-859(CVE-2019-17621) official URL + SHA-256 manifest 기록됨 |
| 실제 펌웨어 AEG 실행 상태 | R7000 V1.0.5.70 vulnerable run은 AutoPoC/poc_validation/verified_chain/FP-FPR gate 통과, V1.0.9.34 patched/control은 dynamic proof fail-closed |
| 승격 전 preflight | `scripts/run_real_firmware_pair_aeg.py`가 공식 pair 분석 실행/재사용 후 `scripts/check_real_firmware_pair_aeg.py`로 펌웨어 SHA-256, vulnerable gate, patched/control fail-closed, 누락 gate artifact를 한 번에 검사 |
| PoC-in-GitHub 사용 방식 | CVE/repo metadata seed → 사람이 검토한 draft pattern card → retriever |
| 금지 사항 | raw PoC clone/실행, raw PoC 전체 prompt 주입, reference endpoint/payload 복붙 |

검증 명령:

```bash
# 모든 curated card가 최소 vulnerable/control pair evidence를 갖는지 확인
python scripts/check_exploit_pattern_evidence.py --require-all

# broad AEG claim 전에는 이 gate도 통과해야 함
python scripts/check_exploit_pattern_evidence.py --require-real-firmware-pair
```

현재 `--require-all`과 `--require-real-firmware-pair`는 checked-in R7000 stable pair evidence 기준으로 통과해야 합니다. 새 firmware input, AutoPoC 동작, pattern card가 바뀌면 `./scout aeg-readiness --out docs/pov/aeg_platform_readiness.json`로 다시 감사해야 합니다.

실제 펌웨어 pair는 **다운로드 가능성**과 **취약성 검증**을 분리해서 다룹니다. `benchmarks/pair-eval/pairs.json`에는 공식 펌웨어 URL과 기대 SHA-256을 기록하고, `scripts/fetch_pair_firmware.py`가 다운로드/기존 파일 검증을 담당합니다. 그러나 이 단계는 "입력 확보"일 뿐이며, `real_firmware_pair` 증거로 승격하려면 vulnerable run은 AEG E2E gate를 통과하고 patched/control run은 fail-closed를 입증해야 합니다.

---

<h2 id="why-scout">💎 SCOUT의 강점</h2>

> **[1] 하이브리드 분석 엔진 (v3)**
> 바이너리 레벨의 실행과 상위 레벨의 쉘 로직 사이의 간극을 메우며, 바이너리 전용 파이프라인이 놓치기 쉬운 스크립트 기반 공격 표면까지 가시성을 확장합니다.

> **[2] 해시 기반의 증거 추적성**
> 모든 탐지 결과는 특정 파일 경로, 바이트 오프셋, SHA-256 해시와 연결됩니다. 블랙박스 기반의 추측이 아닌, 추적 가능한 추론 경로만을 제공합니다.

> **[3] 지능형 분석가 코파일럿**
> 내장된 LLM Tribunal(찬반 토론) 시스템이 등록된 다단계 검증 파이프라인과 과거 Tier-2 벤치마크 기준으로 오탐(False Positive)을 99.3% 줄였습니다.

> **[4] 의존성 제로 (Pure Stdlib)**
> `pip install`의 번거로움이 없습니다. 파이썬 3.10+ 표준 라이브러리만으로 구현되어 폐쇄망이나 제한된 환경에서도 즉시 배포 가능합니다.

---

<h2 id="quick-start">⚡ 빠른 시작</h2>

```bash
# 펌웨어 분석 시작 (하이브리드 모드 기본 활성화)
./scout analyze firmware.bin

# 웹 대시보드 실행
./scout serve aiedge-runs/<run_id> --port 8080

# 터미널 UI(TUI)로 상세 조사
./scout tui

# PoC-in-GitHub 메타데이터만 사용해 Exploit Pattern RAG 후보 seed 생성
python scripts/import_poc_in_github_candidates.py --dry-run

# 후보 하나를 human-review-required pattern card 초안으로 변환
python scripts/draft_exploit_pattern_card.py data/exploit_references/candidates/poc_in_github/cve-2024-1781.json --print-json

# 공식 known-vulnerable/patched 펌웨어 pair를 다운로드하거나 기존 파일 SHA-256 검증
python scripts/fetch_pair_firmware.py --dry-run \
  --pair-id netgear-r7000-cve-2017-5521 \
  --pair-id dlink-dir859-cve-2019-17621
python scripts/fetch_pair_firmware.py \
  --pair-id netgear-r7000-cve-2017-5521 \
  --pair-id dlink-dir859-cve-2019-17621

# 실제 승인된 lab run 이후 동적 증거 + FP/FPR gate 강제
python scripts/aeg_e2e_gate.py aiedge-runs/<run_id>

# evidence + private package metadata를 bounded SCOUT-W Plan IR로 낮춘 뒤,
# private 실행 전에 scope/profile/precondition gate를 fail-closed로 검사합니다.
./scout weaponization-plan aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_plan.json
./scout weaponization-preflight aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/weaponization_preflight.json

# private package metadata를 lint하고 hash-only vault allowlist에 등록합니다.
./scout weaponization-package lint \
  --package-manifest /secure/private/package.manifest.json \
  --out /secure/private/package.lint.json
./scout weaponization-package register \
  --registry /secure/private/package_vault.json \
  --package-manifest /secure/private/package.manifest.json

# 내부 레드팀 private package는 scope, firmware binding, cleanup,
# control-pair, AEG evidence gate 통과 후에만 L6으로 승격합니다.
# 이 명령은 exploit source를 로드하거나 실행하지 않습니다.
./scout weaponization-readiness aiedge-runs/<run_id> \
  --package-manifest /secure/private/package.manifest.json \
  --out aiedge-runs/<run_id>/controlled_weaponization_readiness.json

# plan/preflight/readiness gate 통과 후에만 private package를 실행하고,
# 이어서 L6/L7 execution ledger를 작성합니다.
./scout weaponization-execute aiedge-runs/<run_id> \
  --exploit-dir /secure/private/exploits \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --cleanup-log /secure/private/cleanup.log \
  --vault-registry /secure/private/package_vault.json \
  --approval /secure/private/engagement_approval.json \
  --out-ledger aiedge-runs/<run_id>/weaponization_ledger.json

# 또는 이미 캡처된 실행 증거, cleanup proof, 선택적 engagement approval을
# L6/L7 ledger로 집계합니다.
./scout weaponization-ledger aiedge-runs/<run_id> \
  --plan aiedge-runs/<run_id>/weaponization_plan.json \
  --preflight aiedge-runs/<run_id>/weaponization_preflight.json \
  --readiness aiedge-runs/<run_id>/controlled_weaponization_readiness.json \
  --execution-evidence aiedge-runs/<run_id>/exploits/chain_<id>/evidence_bundle.json \
  --cleanup-log /secure/private/cleanup.log \
  --approval /secure/private/engagement_approval.json \
  --out aiedge-runs/<run_id>/weaponization_ledger.json

# known-vulnerable/patched pair 분석 실행/재사용 + real_firmware_pair 승격 preflight
python scripts/run_real_firmware_pair_aeg.py \
  --pair-id netgear-r7000-cve-2017-5521 \
  --fetch --no-llm \
  --out docs/pov/<stable-pair-evidence>.json

# 이미 승인된 lab run이 있으면 분석을 재사용해서 fail-closed 사전 검사만 수행
python scripts/check_real_firmware_pair_aeg.py \
  --pair-id netgear-r7000-cve-2017-5521 \
  --vulnerable-run-dir aiedge-runs/<known-vulnerable-run> \
  --control-run-dir aiedge-runs/<patched-control-run> \
  --out docs/pov/<stable-pair-evidence>.json

# CI-safe AEG 회귀 테스트: 취약 lab 서비스는 pass, patched/control은 fail-closed
python scripts/run_aeg_synthetic_pair.py --work-root /tmp/scout-aeg-synthetic-pair
python scripts/run_aeg_synthetic_pair.py --pattern cgi_param_cmd_injection --work-root /tmp/scout-aeg-cgi-pair
python scripts/run_aeg_synthetic_pair.py --pattern config_derived_cmd_injection --work-root /tmp/scout-aeg-config-pair

# vulnerable/control 증거가 있는 Exploit Pattern RAG card 확인
python scripts/check_exploit_pattern_evidence.py

# 실제 known-vulnerable/patched 펌웨어 pair 증거를 pattern card에 기록
python scripts/record_pattern_pair_evidence.py <pattern-id> --kind real_firmware_pair \
  --vulnerable-run-dir aiedge-runs/<known-vulnerable-run> \
  --control-run-dir aiedge-runs/<patched-control-run> \
  --artifact docs/pov/<stable-pair-evidence>.json \
  --vulnerable-firmware-sha256 <sha256> \
  --control-firmware-sha256 <sha256> \
  --cve CVE-YYYY-NNNN --apply
```

---

<h2 id="key-features">✨ 핵심 특징</h2>

| | 특징 | 설명 |
|---|---------|-------------|
| :package: | **하이브리드 SBOM & CVE** | CycloneDX 1.6 + VEX + NVD 스캔 + 2,528개 로컬 CVE DB + 통합 쉘 스크립트 감사 |
| :mag: | **바이너리 분석** | Ghidra P-code SSA 데이터플로우 테인 분석 + ELF 보안 설정 탐지 + 28개 위험 심볼 추적 |
| :shell: | **스크립트 분석** | 1,000개 이상의 스크립트 전수 조사 및 위험한 패턴(`eval`, 따옴표 없는 변수, 백틱 등) 탐지 |
| :dart: | **공격 표면 분석** | Source→sink 경로 추적, 웹 서버 자동 탐지, 5개 유형의 바이너리 간 IPC 체인 구성 |
| :brain: | **테인 분석** | HTTP 컨텍스트를 이해하는 절차 간 테인 분석, P-code SSA 데이터플로우 시각화 |
| :robot: | **LLM 엔진** | 4개의 백엔드 지원 + 중앙 집중식 시스템 프롬프트 + 구조화된 JSON 출력 |
| :books: | **Exploit Pattern RAG** | 큐레이션된 pattern-card 검색 + PoC-in-GitHub 메타데이터 seed + 검토된 draft 승격 + vulnerable/control 증거 추적 |
| :crossed_swords: | **LLM 찬반 토론** | Advocate/Critic 모델 간의 토론을 통한 고신뢰도 오탐 제거 |
| :bar_chart: | **웹 뷰어** | KPI 바, IPC 맵, 위험 히트맵 및 증거 탐색 기능을 갖춘 대시보드 제공 |
