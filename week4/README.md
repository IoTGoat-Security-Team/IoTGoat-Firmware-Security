#  OWASP IoTGoat 펌웨어 취약점 보완 및 검증 (4주차)

> OWASP IoTGoat 펌웨어에서 식별된 백도어(`/usr/bin/shellback`)의 **코드 수정(인증 및 권한 제한)**과 중요 파일 권한 취약점(`/etc/shadow`, CWE-732) 보완을 수행하고, 보완 전·후 상태를 검증한 4주차 프로젝트 문서입니다.

---

##  프로젝트 개요

| 항목 | 내용 |
| :--- | :--- |
| **분석 대상** | OWASP IoTGoat 펌웨어 (`IoTGoat-raspberry-pi2`, SquashFS) |
| **실습 환경** | Ubuntu 24.04 LTS (VM) |
| **사용 도구** | Ghidra, QEMU (`qemu-arm-static`), `nc` |
| **4주차 목표** | `/usr/bin/shellback` 코드 수정을 통한 비인가 루트 셸 차단 및 `/etc/shadow` 권한 강화(CWE-732 보완) 검증 |
| **작성일** | 2026-11-27 |

---

##  1. 식별된 주요 취약점

### 1) 비인가 원격 루트 셸 백도어 (`/usr/bin/shellback`)
* **원인:** Ghidra 정적 분석 결과, `/usr/bin/shellback` 바이너리가 `htons(0x158b)`(TCP `5515` 포트)로 소켓을 바인딩한 뒤 별도의 인증 절차 없이 `accept()` 직후 `dup2()`와 `execve("/bin/busybox", ...)`를 호출하여 `root` 권한 셸을 즉시 제공함.
* **위험성:** 외부 공격자가 5515번 포트로 접속하는 것만으로 아이디·비밀번호 검증 없이 기기의 최고 관리자(`root`) 권한을 탈취할 수 있음.

```c
// Ghidra 디컴파일로 확인된 기존 취약 로직 (인증 및 권한 제한 없음)
local_40.sa_family = 2;                          // AF_INET (IPv4)
local_40.sa_data._0_2_ = htons(0x158b);          // TCP 5515 포트 바인딩
__fd = socket(2, 1, 0);
bind(__fd, &local_40, 0x10);
listen(__fd, 1);

do {
    __fd_00 = accept(__fd, &sStack_30, &local_50);
    if (fork() != 0) {
        write(__fd_00, "[***]Successfully Connected to IoTGoat's Backdoor[***]\n", 0x37);
        for (__fd2 = 0; __fd2 < 3; __fd2++) dup2(__fd_00, __fd2);
        execve("/bin/busybox", &pcStack_4c, NULL); // 인증 없이 즉시 root 셸 실행
    }
} while (true);
```

### 2) 중요 자원 권한 설정 미흡 (`/etc/shadow`, CWE-732)
* **원인:** 리눅스 계정 비밀번호 해시가 저장된 `/etc/shadow` 파일의 권한이 `644` (`-rw-r--r--`)로 설정되어 있어, 최저 권한 계정인 `nobody`(UID=`65534`)로도 해시값을 읽을 수 있음.
* **위험성:** 비밀번호가 해시되어 있더라도 해시값이 유출되면 공격자가 자신의 PC에서 **오프라인 크래킹(사전·무차별 대입 공격)**을 수행해 동일한 해시값이 나올 때까지 대입함으로써 원본 `root` 비밀번호를 알아낼 수 있음. 탈취된 `root` 비밀번호는 SSH(22번)나 웹 관리자 페이지(80/443번) 로그인에 악용되어 기기 전체가 장악됨.

---

##  2. 취약점 보완 조치

### 1) `/usr/bin/shellback` 코드 수정 (인증 절차 추가 및 최소 권한 적용)
파일을 삭제하지 않고 원격 관리 기능을 안전하게 유지할 수 있도록, 소켓 연결 수락(`accept()`)과 셸 실행(`execve()`) 사이에 **인증 검증**, **권한 강등(`setgid`/`setuid`)**, **로컬 인터페이스 바인딩 제한** 로직을 추가하여 코드를 보완합니다.

* **사용자 인증 절차 추가:** 접속 직후 인증을 요구하고, 인증에 실패하면 셸을 실행하지 않고 즉시 소켓을 종료(`close`)함.
* **권한 강등(Least Privilege):** 셸 실행 전 `setgid()`와 `setuid()`를 호출하여 `root`(UID=0)가 아닌 일반·저권한 계정으로 권한을 낮춤.
* **바인딩 범위 제한 (권장):** 외부 전체(`INADDR_ANY`) 대신 로컬 루프백(`127.0.0.1`)으로 바인딩하여 외부 직접 노출을 차단함.

```c
// 보완된 shellback 핵심 로직 예시 (인증 추가 + 권한 강등)
struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(5515);
addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1로 바인딩 제한

// ... socket(), bind(), listen() ...

while (1) {
    int client_fd = accept(server_fd, NULL, NULL);
    if (fork() == 0) {
        char buf[64] = {0};
        write(client_fd, "Password: ", 10);
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);

        // 1. 인증 검증 실패 시 즉시 연결 종료
        if (n <= 0 || !verify_auth(buf)) {
            write(client_fd, "Authentication failed.\n", 23);
            close(client_fd);
            _exit(1);
        }

        // 2. root 권한 강등 (최소 권한 원칙)
        if (setgid(65534) != 0 || setuid(65534) != 0) {
            close(client_fd);
            _exit(1);
        }

        // 3. 인증 및 권한 강등 완료 후 셸 실행
        for (int i = 0; i < 3; i++) dup2(client_fd, i);
        char *argv[] = {"/bin/busybox", "sh", NULL};
        execve("/bin/busybox", argv, NULL);
        _exit(1);
    }
    close(client_fd);
}
```

### 2) `/etc/shadow` 소유자 및 권한 강화 (CWE-732 보완)
`/etc/shadow`의 소유자를 `root:root`로 지정하고 권한을 `600` (`-rw-------`)으로 수정하여, 소유자(`root`)만 읽기·쓰기가 가능하도록 제한하고 그룹 및 기타 사용자(`nobody` 등)의 접근을 차단합니다.

```bash
sudo chown root:root ./etc/shadow
sudo chmod 600 ./etc/shadow
```

---

##  3. 보완 조치 검증 결과

| 검증 항목 | 검증 방법 / 명령어 | 보완 전 | 보완 후 (정상 확인) |
| :--- | :--- | :--- | :--- |
| **`shellback` 비인가 접속 차단** | `nc -nv 127.0.0.1 5515` (잘못된 인증 입력) | 인증 없이 즉시 `root` 셸 연결 | `Authentication failed.` 출력 후 연결 종료 |
| **`shellback` 실행 권한 확인** | 인증 통과 후 `id` 명령어 실행 | `uid=0(root) gid=0(root)` | `uid=65534(nobody)` 등 강등된 저권한 확인 |
| **`/etc/shadow` 파일 권한** | `ls -l ./etc/shadow` | `-rw-r--r--` (`644`) | `-rw------- 1 root root` (`600`) |
| **`nobody` 계정 해시 열람 차단** | `sudo chroot --userspec=65534:65534 . /usr/bin/qemu-arm-static /bin/busybox cat /etc/shadow` | 비밀번호 해시 전체 출력 | `cat: can't open '/etc/shadow': Permission denied` |

---

##  4. 결론 및 향후 추가 보안 제언

이번 4주차 보완 및 검증을 통해 `/usr/bin/shellback`의 비인가 루트 셸 취약점을 **코드 수정(인증 추가 및 권한 강등)**으로 해결하고, `/etc/shadow` 권한을 **`600`으로 강화(CWE-732 해결)**하여 저권한 계정을 통한 비밀번호 해시 탈취 및 오프라인 크래킹 위험을 차단했습니다.

###  추가적으로 적용하면 좋은 보안 강화 방안
**방화벽 화이트리스트(Whitelist) 정책 도입:** 5515번 포트만 막는 블랙리스트 방식은 공격자가 바이너리 포트 값(`0x158b`)을 변경하면 우회될 수 있으므로, 추후 네트워크 계층에서 필수 서비스 포트(예: SSH 22, 웹 80/443)만 허용하고 나머지를 기본 차단(`DROP`)하는 화이트리스트 방화벽을 추가하면 보안성을 더욱 높일 수 있음.
