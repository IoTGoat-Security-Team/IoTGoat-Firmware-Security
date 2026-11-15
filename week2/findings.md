# Week 2 — Shellback 취약점 분석 보고서 (`findings.md`)

> **대상:** OWASP IoTGoat Raspberry Pi 2 펌웨어 — `/usr/bin/shellback`  
> **분석 팀:** A팀  
> **분석 방법:** 추출 파일시스템 기반 정적 분석 (`file`, `readelf`, `strings`, `grep`, Ghidra 12.2)  
> **분석 결과:** CWE-306 취약점 **1건**의 정적 코드 근거 확보  
> **검증 범위:** 바이너리 코드·설정 파일 확인까지. 실제 장치에서 접속하거나 취약점을 재현하지 않음.

## 1. 취약점 1 — 인증 없이 원격 셸 기능으로 이어지는 코드 경로

### 1.1 기본 정보

| 구분 | 내용 |
|---|---|
| 식별번호 | `W2-SHELLBACK-01` |
| 제목 | 네트워크 연결 수락 후 인증 검사 없이 BusyBox 셸 실행 시도 |
| CWE | **CWE-306 — Missing Authentication for Critical Function** |
| 분석 파일 | `/usr/bin/shellback` |
| 관련 내부 함수 | `main()` (`0x00010588`) |
| 입력 지점 | TCP 소켓에 대한 `accept()` 결과 |
| 위험 연산 | `execve()`를 통한 BusyBox `sh` 실행 시도 |
| 위험 연산 호출 주소 | `0x0001063C` (함수 자체의 시작 주소가 아니라 **호출 명령의 주소**) |
| 인증 검사 | 확인한 `main()` 연결 처리 경로에서 별도 인증 절차가 보이지 않음 |
| 분석 상태 | **정적 분석 근거 확보, 동적 검증 미실시** |

### 1.2 근거 A — 외부 접속을 받는 코드

Ghidra의 `main()` 역컴파일 화면에서 다음 호출을 확인했다.

```c
/* 실제 Ghidra 화면에서 확인한 호출을 설명용으로 발췌 */
local_40.sa_family = 2;
local_40.sa_data._0_2_ = htons(0x158b);
_fd = socket(2, 1, 0);
bind(_fd, &local_40, 0x10);
listen(_fd, 1);
_fd_00 = accept(_fd, &sStack_30, &local_50);
```

- `sa_family = 2`: IPv4(`AF_INET`) 사용.
- `socket(2,1,0)`: IPv4 스트림 소켓 생성 요청.
- `htons(0x158b)`: 16진수 `0x158b`를 10진수로 변환하면 **5515**.
- `bind()`·`listen()`·`accept()`: 소켓에 주소를 설정하고 연결을 기다린 뒤, 연결을 수락하는 코드.

**해석:** 외부 연결로부터 입력받는 진입 경로가 존재한다. 하지만 이 코드만으로 실제 장치에서 포트가 열려 있는지 또는 외부 인터넷에서 접근 가능한지 판단할 수는 없다.

**관련 증거:** [`shellback-strings-offsets.txt`](evidence/shellback-strings-offsets.txt), [`shellback-string-hits.txt`](evidence/shellback-string-hits.txt), Ghidra `main()` 네트워크 호출 캡처(실습노트 보관).

### 1.3 근거 B — 프로세스 분기, 소켓 입출력 연결, 셸 실행

`main()`의 연결 처리 코드에서 아래 흐름을 확인했다. 아래 코드는 읽기 편하게 축약한 **역컴파일 내용의 요약**이며 원본 소스코드가 아니다.

```c
_Var1 = fork();
if (_Var1 != 0) {
    write(_fd_00, /* Backdoor 연결 알림 메시지 */, /* 길이 */);
    for (_fd2 = 0; _fd2 < 3; _fd2 = _fd2 + 1) {
        dup2(_fd_00, _fd2);
    }
    execve("/bin/busybox", &pcStack_4c, (char **)0x0);
    close(_fd_00);  /* execve 실패 등으로 반환하면 도달 가능 */
}
```

| 함수 | 이번 바이너리에서의 역할 | Ghidra에서 확인한 호출 주소 |
|---|---|---|
| `fork()` | 프로세스 분기 | `0x0001060C` |
| `write()` | 연결 성공을 알리는 메시지를 소켓으로 전송 | `0x00010624` |
| `dup2()` | 수락한 소켓을 fd `0`(입력), `1`(출력), `2`(오류)에 복제 | `0x00010660` |
| `execve()` | `/bin/busybox` 실행 시도 | **`0x0001063C`** |

### 1.4 근거 C — BusyBox `sh` 실행 인자

Ghidra Listing의 데이터 주소 `0x00010791`에 `73 68 00`이 있어, ASCII 문자열 `"sh\0"`임을 확인했다. 인접한 스택 변수의 값도 함께 고려하면 `execve()`의 인자 배열은 다음과 같이 해석된다.

```text
argv[0] = "/bin/busybox"
argv[1] = "sh"
argv[2] = NULL
```

또한 Listing에서 다음 ARM 호출 명령을 확인했다.

```asm
0001063c    bl    <EXTERNAL>::execve
```

**해석:** 연결 소켓을 표준 입출력에 연결한 뒤 BusyBox의 `sh` 셸 실행을 시도하도록 작성되어 있다. `0x0001063C`는 **Shellback 내 호출 지점**이며, 외부 라이브러리 `execve()` 자체의 시작 주소가 아니다.

### 1.5 취약점으로 판단한 근거

확인된 연결 수락부터 셸 실행 시도까지의 `main()` 경로에는 사용자명·비밀번호 등 **별도의 인증 검사나 접근 승인 조건이 보이지 않는다.** 이 코드가 실제로 실행되고 공격자가 해당 TCP 서비스에 접근할 수 있다면, 연결된 소켓을 통해 셸 명령 입출력을 주고받을 위험이 있다.

다만 **현재 기록은 실제 침투 성공이나 원격 명령 실행 성공을 증명하지 않는다.** 함수의 정적 호출 경로를 근거로 CWE-306 취약점으로 분류하였다.

## 2. 공개 해설·패치와의 비교 상태

| 비교 항목 | 내 정적 분석 결과 | 비교 상태 |
|---|---|---|
| 백도어 연결 메시지 | `Successfully Connected to IoTGoat's Backdoor` 문자열 확인 | **일치.** [OWASP 공식 해설][owasp-solutions]에서도 TCP 5515 접속 직후 `[***]Successfully Connected to IoTGoat's Backdoor[***]` 메시지가 표시된다. |
| 리슨 포트 | `htons(0x158b)`로 설정된 **TCP 5515번 포트**를 `socket() → bind() → listen() → accept()` 흐름에 사용함을 확인 | 공식 해설에서는 포트 스캔 결과 `5515/tcp open unknown`으로 표시하고 해당 서비스를 조사하도록 안내한다. 우리는 Shellback의 정적 분석을 통해 **5515번이 연결을 대기하도록 설정된 백도어 소켓의 포트**임을 확인했다. 실제 리슨 성공 여부는 직접 검증하지 않았다. |
| 셸 실행 방식 | `/bin/busybox`와 인자 `sh`, 소켓을 표준 입출력에 연결하는 `dup2()`, 프로그램을 실행하는 `execve()` 호출 확인 | **기능 일치, 구현 상세는 직접 분석.** [OWASP 공식 해설][owasp-solutions]은 5515번 포트에 연결한 후 명령을 실행하여 대화형 셸을 획득하는 실습을 안내한다. [외부 분석 사례][revers0-analysis]에서도 해당 포트를 통해 셸에서 명령을 실행한 결과를 보여준다. `dup2()`와 `execve()`의 **구체적인 호출 구조**는 우리가 ARM 바이너리를 Ghidra로 분석해 추가로 확인했다. |
| 인증 검증 | 확인한 `main()` 연결 처리 경로에서 별도 사용자 인증 검사 없음 | **일치.** [OWASP 공식 해설][owasp-solutions]은 별도의 로그인 과정 없이 5515번 포트에 접속해 셸 명령을 시도하도록 안내하며, [공개 실행 사례][revers0-analysis]에는 별도 인증 없이 명령을 실행한 결과가 제시되어 있다. 우리는 Ghidra에서 **연결 수락부터 셸 실행 시도까지 인증 검사가 없는 코드 경로**를 확인했다. |
| 부팅 등록 | `/etc/rc.d/S95shellback`, `/etc/config/shellback`의 `enabled=1`, `/etc/rc.local`의 직접 실행 명령 확인 | **일치.** [OWASP 공식 해설][owasp-solutions]은 Shellback을 **부팅 시 실행되도록 구성된 지속형 백도어**로 소개한다. [별도 펌웨어 분석 보고서][firmware-report]에는 `/etc/init.d/shellback`의 `START=95`, `enabled=1`, `/etc/rc.local`의 `/usr/bin/shellback &`가 기록되어 있다. 우리도 추출한 펌웨어에서 해당 설정과 `S95shellback` 링크를 직접 확인했다. |

**비교 범위:** OWASP 공식 해설과 공개된 분석 사례를 대조했다. 공개 사례의 실제 셸 접속 성공은 **다른 연구자의 검증 결과**이며, 이번 실습에서 직접 동적 검증을 수행했다는 뜻은 아니다. 또한 공개된 별도 펌웨어 분석 보고서에는 x86 이미지 분석이 포함되므로, ARM 바이너리의 함수와 주소는 **우리가 수행한 Ghidra 분석 결과**를 기준으로 적었다. 공식 패치의 변경 내용까지 대조하지는 않았다.

**참고한 공개 자료**

- [OWASP IoTGoat Wiki — Challenge solutions][owasp-solutions] (공식 해설: 5515 포트, 백도어 접속 메시지, 셸, 부팅 실행)
- [revers0 — OWASP IoTGoat Solutions][revers0-analysis] (외부 실습: 5515 포트 접속 및 셸 명령 실행)
- [IoTGoat Firmware Vulnerability Assessment Report][firmware-report] (별도 이미지 분석: 시작 스크립트 및 활성화 설정)

[owasp-solutions]: https://github.com/OWASP/IoTGoat/wiki/Challenge-solutions
[revers0-analysis]: https://www.revers0.com/posts/iotgoat/
[firmware-report]: https://github.com/ASCIT31/darkmoon-research/blob/main/reports/iot/iotgoat-firmware-image.md
