# SCOUT: Surface Candidate Outline & Unified Triage
**Agent 기반 IoT 펌웨어 취약점 후보 자동 생성 시스템**
*(Agent-based Vulnerability Candidate Generation for IoT Firmware)*

SCOUT는 IoT 펌웨어의 공격면(Attack Surface)을 정찰하고, 증거(Evidence)를 기반으로 실제로 검증해볼 가치가 있는 취약점 후보(Vulnerability Candidate)를 자동으로 생성하는 시스템입니다.

## 🚀 Key Features

*   **Multi-Tool Integration**: EMBA (정적), FirmAE (동적), Ghidra (코드), IDA Pro(Optional) 등 도구 자동 실행
*   **Fact-Based Reasoning**: 도구의 로그에서 '사실(Fact)'과 '증거(Evidence)'를 추출하여 분석
*   **LLM Agent Synthesis**: 수집된 정보를 바탕으로 취약점 후보를 추론하고, 검증 우선순위와 재현 가이드 제시
*   **Real-Time Dashboard**: CLI 기반의 TUI(Terminal UI) 대시보드 (`tui_app.py`) 제공

---

## 🛠 Prerequisites & Installation

SCOUT는 **Linux 환경 (Ubuntu 20.04/22.04 LTS 권장)** 또는 **WSL2**에서 실행해야 합니다.

### 1. 필수 의존성 설치
**Python 3.10+** 및 필수 라이브러리를 설치합니다. (FirmAE 등을 위해 `root` 권한 필요)

```bash
# 시스템 패키지 업데이트
sudo apt update && sudo apt install -y python3-pip docker.io

# SCOUT 필수 라이브러리 설치 (Sudo 필수!)
# 주의: FirmAE 호환성을 위해 capstone 버전을 5.0 미만으로 고정해야 할 수 있습니다.
sudo pip3 install "capstone<5.0" pydantic python-dotenv openai textual
```

### 2. 외부 도구 준비
*   **Docker**: EMBA 실행을 위해 Docker가 설치 및 실행 중이어야 합니다 (`sudo systemctl start docker`).
*   **FirmAE**: 홈 디렉토리 등 접근 가능한 경로에 설치되어 있어야 합니다 (SCOUT는 기본적으로 `~/FirmAE`를 탐색).
*   **Ghidra (Optional)**: 코드 분석을 위해 `analyzeHeadless`가 PATH에 있거나 `GHIDRA_HEADLESS_PATH` 환경변수 설정 필요.

---

## 📖 Usage

### 1. Mock Mode (테스트 실행)
펌웨어 파일 없이 샘플 데이터를 사용하여 파이프라인 전 과정을 테스트합니다.
```bash
python3 scout.py
```

### 2. Real Mode (실전 분석)
실제 펌웨어를 분석합니다. **반드시 `sudo` 권한으로 실행해야 합니다.** (FirmAE/Binwalk 권한 문제 해결)

```bash
# 1. 파일명에 공백이 없도록 변경 (필수!)
mv "firmware/Gyul Cam v1.14.bin" "firmware/Gyul_Cam_v1.14.bin"

# 2. 실행
sudo python3 scout.py --firmware "firmware/Gyul_Cam_v1.14.bin"
```

### 3. TUI Dashboard (대시보드)
분석 진행 상황이나 결과를 그래픽하게 확인하려면 TUI를 실행하세요.
```bash
python3 tui_app.py
```

---

## 📂 Project Structure

```bash
scout/
├── collect/       # 외부 도구 실행 모듈 (emba_runner, firmae_runner 등)
├── normalize/     # 로그 파싱 및 표준화 모듈 (Parser)
├── agent/         # LLM 프롬프트 및 추론 로직 (Core Agent)
├── validate/      # 데이터 검증 및 룰 기반 필터링
├── report/        # 리포트 생성 (Markdown/JSON)
├── firmware/      # 분석할 펌웨어 저장소
└── tui_app.py     # 터미널 UI 대시보드
```

---

## ⚠️ Troubleshooting

1.  **Permission Denied (Binwalk/FirmAE)**
    *   원인: 펌웨어 추출 시 root 권한이 필요합니다.
    *   해결: `sudo python3 scout.py ...` 명령어로 실행하세요.

2.  **`capstone` Error (AttributeError: CS_ARCH_ARM64)**
    *   원인: 최신 capstone 5.0+ 버전 호환성 문제.
    *   해결: `sudo pip3 install "capstone<5.0"` 로 다운그레이드 하세요.

3.  **EMBA 오류 (Code 126/127)**
    *   원인: Docker 이미지 버전이나 스크립트 경로 문제.
    *   해조: 현재 `embeddedanalyzer/emba` 이미지를 사용 중이며, 실패하더라도 SCOUT는 건너뛰고 나머지 분석(FirmAE/Agent)을 수행합니다. 만약 EMBA가 필수라면 추후 Binwalk 추출 후 수동 분석이 권장됩니다.
