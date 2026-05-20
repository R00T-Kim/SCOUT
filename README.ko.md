<p align="right">
  <a href="README.md">English</a> |
  <strong>한국어</strong>
</p>

# SCOUT (v3.0.0-rc1)

### 결정론적 증거 체인을 활용한 하이브리드 펌웨어 보안 분석 코파일럿

**SCOUT은 가공되지 않은 펌웨어 바이너리를 분석하여, 증거 기반의 실행 가능한 보안 보고서로 변환하는 딥 분석 파이프라인입니다. 이제 바이너리와 쉘 스크립트를 동시에 감사하는 하이브리드 분석 엔진을 탑재했습니다.**

*기존의 스캐너들이 탐지 수량과 속도에만 치중할 때, SCOUT은 분석가를 위한 고신뢰도 코파일럿 역할을 수행합니다. 단순한 CVE 목록을 나열하는 대신, ELF 바이너리와 쉘 스크립트를 가로지르는 익스플로잇 체인을 재구성하고, 증거 기반의 추론 과정을 통해 검증된 PoC를 생성합니다.*

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
- **PoC 자동 생성**: **Exploit Pattern RAG**를 활용하여 실험실 검증용 Proof-of-Vulnerability 모듈을 생성합니다.
  - SCOUT은 firmware-relevant CVE seed를 위해 PoC-in-GitHub 메타데이터 전용 importer를 포함하며, AutoPoC 검색에 쓰기 전 curated exploit pattern card로 승격하는 절차를 요구합니다.
  - SCOUT은 raw 공개 PoC 저장소를 clone/실행/prompt 주입하지 않습니다. 자세한 내용은 [`docs/exploit-pattern-rag.md`](docs/exploit-pattern-rag.md)를 참고하세요.
- **증거 기반 조사**: 글래스모피즘 웹 대시보드를 통해 디컴파일된 P-code와 쉘 로직을 시각적으로 조사합니다.
- **감사/규제 대응형 보고**: SARIF, CycloneDX 1.6 SBOM+VEX, SLSA L2 증명서를 생성합니다.

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
./scout ti

# PoC-in-GitHub 메타데이터만 사용해 Exploit Pattern RAG 후보 seed 생성
python scripts/import_poc_in_github_candidates.py --dry-run
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
| :books: | **Exploit Pattern RAG** | 큐레이션된 pattern-card 검색 + PoC-in-GitHub 메타데이터 기반 firmware 후보 seed |
| :crossed_swords: | **LLM 찬반 토론** | Advocate/Critic 모델 간의 토론을 통한 고신뢰도 오탐 제거 |
| :bar_chart: | **웹 뷰어** | KPI 바, IPC 맵, 위험 히트맵 및 증거 탐색 기능을 갖춘 대시보드 제공 |
