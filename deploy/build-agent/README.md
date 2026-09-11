# 打包机部署

**这台机器不和 wallet 后端同机。** 它持有 Android keystore，而"服务端不下发密钥、不执行命令"那套论证在两者同机的那一刻就作废了：后端的一个 RCE 直接读到磁盘上的密钥。

## 目录约定

| 路径 | 内容 | 删了会怎样 |
| --- | --- | --- |
| `/opt/rn-build-agent/build-agent` | 程序本体 | 重新 scp 一个 |
| `/etc/rn-build-agent.env` | 配置，0600 root 所有 | 要重新填，含 keystore 口令 |
| `/var/lib/rn-build-agent/` | 状态，同时是 builder 的 HOME | 要重新配部署密钥、重新拉仓库 |
| `/var/lib/rn-build-agent/repos/rn-app.git` | 仓库镜像（裸库） | 重新 clone |
| `/var/lib/rn-build-agent/workspace/` | 每个任务一个临时 worktree | 无所谓，任务结束就删 |
| `/var/lib/rn-build-agent/.ssh/` | GitHub 部署密钥 | 要重新生成并加回仓库 |
| `/var/cache/rn-build-agent/` | Gradle 与 pnpm 的缓存 | 只是下一次构建慢一点 |
| `/opt/android-sdk` | Android SDK，root 所有、全局可读 | 重新装 |

状态与缓存分开不是形式：清理策略和备份策略完全不同。

## 装一台新的

```bash
# 1. 工具链
sudo apt-get install -y openjdk-17-jdk-headless
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs
sudo corepack enable && sudo corepack prepare pnpm@latest --activate

# 2. Android SDK 到 /opt，root 所有、全局可读（构建用户不需要写它）
sudo mkdir -p /opt/android-sdk/cmdline-tools && cd /tmp
curl -sSLo cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
sudo unzip -qo cmdline-tools.zip -d /opt/android-sdk/cmdline-tools
sudo mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest
yes | sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --install \
  "platform-tools" "platforms;android-36" "build-tools;36.0.0" "build-tools;35.0.0" \
  "ndk;27.0.12077973" "ndk;27.1.12297006" "cmake;3.22.1"
sudo chmod -R a+rX /opt/android-sdk
# SDK 目录对构建用户只读是有意的，所以 NDK 版本必须**预装齐**：Gradle 想自己装
# 一个缺失的 NDK 时会失败在"SDK directory is not writable"，而不是去装。
# 版本号以 expo-updates / react-native 当前要求的为准，装漏了构建到一半才会知道。

# 3. 用户与目录。家目录就是状态目录：OpenSSH 按 passwd 里的 home 找 ~/.ssh，
#    不看 $HOME，所以两者必须一致
sudo useradd --system --create-home --home-dir /var/lib/rn-build-agent --shell /bin/bash builder
sudo mkdir -p /var/lib/rn-build-agent/{repos,workspace} /var/cache/rn-build-agent/{gradle,pnpm-store} /opt/rn-build-agent
sudo chown -R builder:builder /var/lib/rn-build-agent /var/cache/rn-build-agent

# 4. 部署密钥，公钥加到仓库的 Deploy keys（只读）
sudo -u builder ssh-keygen -t ed25519 -N "" -C "rn-build-agent@$(hostname)" -f /var/lib/rn-build-agent/.ssh/id_ed25519
sudo -u builder ssh-keyscan -t ed25519 github.com | sudo -u builder tee /var/lib/rn-build-agent/.ssh/known_hosts
sudo cat /var/lib/rn-build-agent/.ssh/id_ed25519.pub

# 5. 仓库镜像
sudo -u builder git clone --mirror git@github.com:Helix2010/RN-App.git /var/lib/rn-build-agent/repos/rn-app.git

# 6. 程序、配置、服务
sudo install -m 0755 build-agent /opt/rn-build-agent/build-agent
sudo install -m 0600 rn-build-agent.env.example /etc/rn-build-agent.env   # 然后填
sudo install -m 0644 rn-build-agent.service /etc/systemd/system/
sudo systemctl enable --now rn-build-agent
```

## 排查

```bash
sudo journalctl -u rn-build-agent -f
```

构建失败的原因和日志尾部也会回到服务端，在管理端的构建记录里能看到——不必登到这台机器上才知道出了什么事。
