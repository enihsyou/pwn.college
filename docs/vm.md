# Windows 本地测试 VM

这是在 **Windows 上运行测试 VM** 的一种方式。为了缓解连接 pwn.college 的网络延迟，以及远程挑战环境运行速度慢的问题，这里复刻了一遍启动环境：Windows 原生 QEMU 跑虚拟机，WSL 构建文件系统和运行 GDB，rsync 从当前挑战拉取文件。整个方案比较别扭，也无法完整还原官方环境。

**更推荐使用官方发布的 [pwncollege/challenge-legacy 镜像](https://hub.docker.com/r/pwncollege/challenge-legacy)**，在适合运行该镜像的环境中使用官方工具。本脚本是需要 Windows 原生 QEMU 时的替代方式。

## 前置条件

- Windows x86_64，启用开发者模式或具有创建符号链接的权限。
- PATH 中有 `uv`、原生 Windows `qemu-system-x86_64`、`ssh`、`scp`、`ssh-keygen`、MSYS `rsync` 和 `cygpath`。
- `gh` 可访问 GitHub API，用于从官方仓库的软链接元数据确定内核版本。
- 已配置 dojo SSH 认证；默认使用 `hacker@dojo.pwn.college`。与 `task pull` 相同，rsync 使用 `/usr/bin/ssh`，避免混用 Windows OpenSSH 导致协议握手失败。
- 已有 x86_64 Ubuntu/Debian WSL 发行版，默认名称 `Ubuntu`。其中需要 `bash`、`apt-get`、`dpkg-deb`、`cpio`、`gzip`、`openssl` 和常见 GNU 工具；调试另需 `gdb`、`nm`。
- WSL 软件包索引可用，软件源允许下载 `busybox-static`、`dropbear-bin`、`openssh-sftp-server`、`python3.14`、`rsync` 及其依赖。构建器仅下载并解包 guest 软件包，不安装到 WSL，也不调用 sudo。
- 使用 WSL GDB 时需要 WSL 的 mirrored networking，使 WSL 能访问 Windows 的 `127.0.0.1`。SSH 连接使用 Windows 客户端，不受这一限制。
- 仓库 `.env` 配置 `DOJO_ACCESS_TOKEN`，并在网站上启动目标挑战。

## 启动与日常操作

在仓库根目录运行：

```powershell
# API 确认当前 challenge，下载文件并生成文件系统，到此结束，不启动 VM
uv run --env-file .env python -m scripts.vm prepare

# 只使用本地准备结果，后台启动并等待 SSH，无需 API、网络或 WSL 构建
uv run python -m scripts.vm start

# 连接为 hacker，UID/GID 1000
uv run python -m scripts.vm connect

# 上传单个文件；省略目标路径时放入 /home/hacker/
uv run python -m scripts.vm cp ./exploit /home/hacker/
uv run python -m scripts.vm cp ./payload.py

# 上传目录，目标路径是 guest 内的路径
uv run python -m scripts.vm cp -r ./payloads /home/hacker/

# 执行命令；需要管道、重定向时显式使用 shell
uv run python -m scripts.vm exec id
uv run python -m scripts.vm exec python3 --version
uv run python -m scripts.vm exec sh -c 'cat /proc/cmdline; ls -l /challenge'

# 查看串口与 QEMU 日志，-f 持续跟随，Ctrl+C 退出查看
uv run python -m scripts.vm logs
uv run python -m scripts.vm logs -f

# 复用已准备的 initramfs 重启，保留之前的启动选项
uv run python -m scripts.vm restart

# 仅停止选中的实例，保留文件与日志
uv run python -m scripts.vm stop

# WSL GDB 连接 QEMU，加载内核和挑战模块符号
uv run python -m scripts.vm debug
```

`prepare` 需要 API 与 dojo SSH 可用，完成后保存 `prepared.json` 并退出，不启动 QEMU。`start` 只读取本地准备结果，不查询 API、不同步文件、不重新构建镜像；同一题目已经运行时直接复用，不修改启动选项。`restart` 同样只复用已准备的镜像。需要重新同步文件、更新 guest 初始化源码或将本地挑战目录的修改打包进镜像时，先 `stop`，再 `prepare`、`start`；`prepare` 会拒绝修改仍在运行的目标实例，不自动停止它。

准备和启动后的管理命令默认选择最近准备或启动的实例。`start`、`restart` 仍需该实例的 TEMP 挑战目录和缓存文件存在；`debug` 使用 WSL GDB，其余管理操作不需要 WSL 构建工具。

管理命令默认选择最近启动的实例。全局参数放在子命令前，可指定另一个已保存实例：

```powershell
uv run python -m scripts.vm --instance software-exploitation/kernel-exploitation/level7 stop
```

实例 ID 必须使用 API 的实际 dojo/module/challenge ID，示例名称不一定与当前课程一致。脚本不会切换网站上的挑战。

`prepare` 会将宿主 `~/.ssh/id_ed25519.pub`（当前 Windows 用户对应 `C:/Users/enihsyou/.ssh/id_ed25519.pub`）加入 `hacker` 的授权公钥。`start` 成功后会显示一行可直接复制的连接命令，例如 `ssh 127.0.0.1 -l hacker -p 4280`；SSH 使用宿主默认私钥，无需指定 `-i`。宿主公钥不存在时仍可使用实例专用密钥，通过 `connect` 连接。

`cp` 自动读取实例的 SSH 端口、专用密钥和 known_hosts，无需传入这些参数。复制目录必须带 `-r`；同路径文件按 SCP 的行为覆盖，不删除目标目录中的额外文件。

## 挑战标记与启动选项

默认遵循上游 VM 的文件标记，而不是实验脚本里固定开启的选项：

| 标记 | 存在时 | 不存在时 |
| --- | --- | --- |
| `.kaslr` | 不传 `nokaslr`，允许内核启用 KASLR | 传 `nokaslr` |
| `.panic_on_oops` | 传 `oops=panic panic_on_warn=1` | 不额外开启 panic |
| `.nopti` | 传 `nopti` | 不额外关闭 PTI |

命令行覆盖标记，`restart` 未指定的选项沿用上次的有效值：

```powershell
uv run python -m scripts.vm start --kaslr --panic-on-oops
uv run python -m scripts.vm restart --no-kaslr --no-panic-on-oops
uv run python -m scripts.vm restart --no-pti
```

Windows QEMU 使用 `-accel tcg -cpu qemu64,+smep,+smap -m 2G -smp 1`。TCG 不需要 KVM，但并不保证比所有远程环境都快。启动后显示 SSH 端口、日志路径和等待时间；SSH 默认等待 180 秒，可用 `start --timeout 300` 或 `restart --timeout 300` 调整。检测到本次启动日志中的 kernel panic 会立即报错。超时或 panic 都会保留 VM，便于查看日志和停止；不会自动杀进程。

## 文件、缓存与文件系统

默认缓存目录为 `%LOCALAPPDATA%/pwn-college/vm`，包括：

- `downloads/`：按 HEAD 返回的原始附件文件名保存 `vmlinux0` 至 `vmlinux3`。
- `kernels/<版本>/bzImage`：官方 dojo 固定提交中的对应启动内核。
- `remote/<来源标识的摘要>/`：其他大文件。标识包含 SSH 主机和真实来源路径；直接位于 `/challenge` 的文件还包含题目 ID，避免不同题目的同名文件混用。摘要不读取或比较文件内容哈希。
- `rootfs/`：guest 软件包缓存和按发行版区分的基础 initramfs。
- `instances/<dojo>/<module>/<challenge>/`：SSH 密钥、主机密钥、known_hosts、生成的 initramfs、准备结果 `prepared.json`、运行状态 `state.json` 和日志。
- `last.json`：最近准备或启动的实例。

挑战工作目录固定为 `%TEMP%/pwn-college-vm/<dojo>/<module>/<challenge>/`，同一题目重复准备会复用。例如当前题目为 `software-exploitation/kernel-exploitation/level7`、TEMP 为 `R:/TEMP` 时，目录为 `R:/TEMP/pwn-college-vm/software-exploitation/kernel-exploitation/level7/`。同步保留点文件，自动将 `bzImage`、`vmlinux` 和其他至少 3 MiB 的文件分流到独立缓存，避免每次挑战 rsync 重复传输。缓存就绪后，在挑战目录创建 Windows 原生软链接。重新 `prepare` 会同步远端文件，并刷新启动标记和 `.initvm`；本地额外添加的文件不会批量删除。

已知 software-exploitation 内核优先根据 dojo 上的真实来源路径识别版本。如果容器中是普通文件，来源只剩 `/challenge/vmlinux`，则通过 `gh api` 读取官方固定提交中当前题目的 `vmlinux` 软链接目标，例如 `level7/vmlinux -> ../files/2/vmlinux`，不按题目编号猜版本。`vmlinux` 来源沿用官方 Dockerfile；Dropbox 使用能返回原始文件名的 `dl.dropboxusercontent.com` 入口。HEAD 先取得 `Content-Disposition` 文件名，存在同名缓存就跳过下载，不比较哈希。缺失或返回 `unspecified` 的文件名会报错，不共用一个含糊的缓存名。

GitHub Raw/Release 下载在完整原始 URL 前加 `https://gh-proxy.org/`。`bzImage` 的 Raw 响应不保证提供附件名，因此按版本目录中的固定文件名缓存。无法识别来源的内核文件会报错，要求显式指定 `--kernel`/`--vmlinux`，不会退回 rsync。其他大文件首次用 rsync 拉取，之后按来源路径复用；同一路径内容更新时，需要在停止相关实例后手动移走该缓存文件再启动。

缓存可改位置，后续每条命令需要使用同一位置：

```powershell
uv run --env-file .env python -m scripts.vm --cache D:/Cache/pwn-college-vm prepare
uv run python -m scripts.vm --cache D:/Cache/pwn-college-vm start
uv run python -m scripts.vm --cache D:/Cache/pwn-college-vm connect
```

基础文件系统由 `scripts/vm_assets/build.sh` 生成并缓存，`scripts/vm_assets/init` 是 guest 的 `/init` 源码。`prepare` 复用基础文件系统，加入本次挑战、实例 SSH 配置，再生成 initramfs；不要手改生成的 cpio 文件。构建只在 WSL 创建的专用临时目录内解包，结束后只清理该构建目录，不在仓库根目录解包。

guest 中包含 BusyBox、Dropbear SSH、供 `scp` 使用的 SFTP server、Python 3.14 及标准库、rsync、`hacker` 用户和 root 所有、权限 `0400` 的 `/flag`，内容为 `pwn.college{practice}`。`python3` 指向 `python3.14`，不预装第三方 Python 包。SSH 只允许密钥登录并禁用 root 登录；授权公钥包含实例专用密钥的公钥，以及构建时存在的宿主 `~/.ssh/id_ed25519.pub`。实例管理命令使用专用密钥与固定的主机密钥校验，不读取实验目录中的私钥，也不复制宿主私钥到 guest。

**复用的是生成的文件系统镜像，guest 运行期间修改的文件位于内存中，重启后丢失。** 宿主 TEMP 中的挑战文件可以编辑，重新 `prepare` 才会打包进镜像；`start` 和 `restart` 不重新打包。VM 中没有共享挂载整个 Windows 文件系统，也没有持久化磁盘。

## 调试与隔离

每个实例分配独立的 SSH、GDB 和 QMP 空闲端口，全部只监听 `127.0.0.1`。后台 QEMU 的输出写入实例 `vm.log`，不额外弹出窗口。

### 用 task sync 和 task submit 传文件

复用 `DOJO_HOST` 指定 IP，并用 `DOJO_PORT` 指定实例的端口，不需要配置 SSH 别名。`prepare` 已加入宿主公钥时，SSH 自动使用宿主默认私钥，无需设置 `DOJO_KEY`。以下命令从默认缓存中读取最近实例；使用自定义 `--cache` 时相应修改 `$vmCache`：

```powershell
$vmCache = Join-Path $env:LOCALAPPDATA 'pwn-college/vm'
$vmInstance = (Get-Content "$vmCache/last.json" -Raw | ConvertFrom-Json).instance
$vmState = Get-Content "$vmCache/instances/$vmInstance/state.json" -Raw | ConvertFrom-Json
$vmConnection = @(
    'DOJO_HOST=hacker@127.0.0.1'
    "DOJO_PORT=$($vmState.ssh_port)"
    "DOJO_KNOWN_HOSTS=$($vmState.known_hosts)"
)

# 同步 workspace/home/hacker/ 到 VM 的 /home/hacker/，跳过 __pycache__
task sync @vmConnection

# 上传当前题目的解题文件及同目录文件，执行并监听本地修改
task submit @vmConnection

# 只上传，保留修改后自动重新上传的行为；Ctrl+C 退出
task submit @vmConnection -- --upload-only
```

不指定这些变量时，两个 task 均连接官方 dojo。`task submit` 仍通过网站 API 确定题目，因此网站当前题目必须与 VM 中的题目一致；`DOJO_HOST` 只改变 SSH 目的地。重启 VM 后重新读取 `state.json`，端口可能变化。

`task sync` 会覆盖同路径文件，不删除 VM 中的额外文件；传输不要求重启 VM。`task submit` 会通过 `PYTHONPATH` 导入同步后的 `dojotool`，其源码目前位于 `.local/lib/python3.13/site-packages`，guest 使用 Python 3.14 也可以导入。guest 未预装 pwntools、编译器或 Bash，依赖这些工具的解题文件仍需补齐环境；`dojotool.submit()` 调用的官方 `dojo submit` 也不在该最小 VM 中。

修改宿主公钥后需要先 `stop`、`prepare`、`start`，新公钥才会写入镜像。guest 文件在内存中，停止或重启前应先保存需要保留的文件。

也可直接使用 SCP，端口来自 `state.json`：

```powershell
# 将 <SSH端口> 替换为 state.json 中的值；scp 的端口参数是大写 -P
scp -P <SSH端口> ./exploit hacker@127.0.0.1:/home/hacker/
```

`stop`、`restart` 操作前通过 QMP 的 `query-uuid` 核对 VM 身份，然后只向该实例发送 `quit`；不按进程名停止 QEMU，也不凭旧 PID 杀进程。端口被其他实例占用或 UUID 不符时会报错。

guest 加载 `/challenge` 中的 `.ko`，再执行 `.initvm`，最后通过第二串口导出实际 `_text` 地址和模块各 section 地址。`debug` 从匹配 `vmlinux` 的 `_text` 计算 KASLR 偏移，给 GDB 加载重定位后的内核及模块符号，不固定内核基址、模块内部名称或端口。SSH 仍是 UID 1000 用户，符号地址通过启动时的 root 初始化取得。

下载的 `vmlinux` 包含调试符号，不包含内核源码。GDB 提示源码文件不存在时，仍可查看符号、寄存器、内存和反汇编；源码级调试需要另外准备源码并配置 GDB 的源码搜索路径。

停止虚拟机前先退出 GDB，以免 GDB 的运行控制影响停止过程。调试通道能控制 guest 内核，SSH 私钥能登录 guest；缓存目录应只供当前 Windows 用户访问，不要提交其中的文件。

## 扩展到其他 challenge

通用同步、生命周期和启动标记不绑定某一题；已知内核下载来源集中在 `scripts/vm.py` 的 `VMLINUX_URLS`、`resolve_kernel_sources()` 和 `cached_asset()` 中。其他大文件使用独立 rsync 缓存；未知内核必须显式指定文件。

其他内核可以显式指定本地镜像与匹配的符号文件，也可以选择不同的 WSL 发行版和 QEMU 路径：

```powershell
uv run --env-file .env python -m scripts.vm prepare --kernel D:/kernels/bzImage --vmlinux D:/kernels/vmlinux --wsl Ubuntu
uv run python -m scripts.vm start --qemu C:/QEMU/qemu-system-x86_64.exe
```

首次需要从 API 确定当前题目，并同步其 `/challenge`。guest 内核需要支持 x86_64、gzip initramfs、串口、devtmpfs、e1000 与相应网络能力。新增受支持的官方下载来源时，在来源解析处添加映射即可，无需复制 VM 管理代码。

该最小文件系统面向内核挑战，不是完整 Ubuntu：依赖第三方 Python 包、完整 systemd、Docker 或额外工具的 `.initvm` 可能不能运行；含依赖关系的多个内核模块需要按挑战需要调整加载顺序。远程 `/challenge/.init` 属于宿主挑战容器初始化，本脚本不在 Windows/WSL 执行它。需要完整环境时优先使用官方镜像。

## 参考

- [上游 VM 启动脚本](https://github.com/pwncollege/challenge-images/blob/e7961e95ea520b2564d26255b76bf2e6edaa665d/legacy/vm/vm)
- [上游 guest init](https://github.com/pwncollege/challenge-images/blob/e7961e95ea520b2564d26255b76bf2e6edaa665d/legacy/vm/init)
- [vmlinux 来源 Dockerfile](https://github.com/pwncollege/challenges/blob/0a4d91514c8077a5b77c25aff3ce2d6dc90c1181/challenges/legacy/common/Dockerfile.j2#L17)
- [本脚本固定的 bzImage 来源提交](https://github.com/pwncollege/software-exploitation-dojo/tree/314c1135d3601fea2d313063bdc5fbf6fb1701cd/kernel-exploitation/files)
