# 自用版指向说明

> 本包已去掉 VMess、加上 Hysteria2 / TUIC，并且不再默认指向
> 上游 vioIetMiku/miku-gate。但你没有在对话里给过自己的仓库名，
> 所以这里**没有猜一个用户名**，而是留了一个占位，发布前换一次即可。

## 发布前只做一件事

在整个包里搜索 `YOUR_GITHUB_USER`，全部换成你自己的 GitHub 用户名
（仓库名保持 `miku-gate` 不变；如果你仓库名也改了，连同改掉）。

换完之后，安装命令自然变成自用版：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/miku-gate/main/mikugate.sh)
```

不想改文件时，也可以运行时传环境变量，效果一样，环境变量优先：

```bash
MIKU_GATE_REPO=你的用户名/miku-gate bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/miku-gate/main/mikugate.sh)
```

占位没换就直接运行安装脚本时，脚本会报错停下，不会悄悄装回上游版本。

## 这次改了哪些指向

- `mikugate.sh`：下载 `install-online.sh` 的地址，改成
  `https://github.com/${MIKU_GATE_REPO}/releases/latest/download/install-online.sh`，
  默认占位 `YOUR_GITHUB_USER/miku-gate`。
- `install-online.sh`：GitHub API 地址改成
  `https://api.github.com/repos/${MIKU_GATE_REPO}`，同样用占位兜底。
- `src/update.go`：更新检查仓库改成 `updateRepoValue()`，
  优先读 `MIKU_GATE_REPO` 环境变量，否则用占位；
  原来这里写的是上游 fanout 仓库，也一并改掉了。
- `src/main.go`：更新检查返回的仓库链接改成跟上面同一处。
- `README.md`、`scripts/release-notes.md`：安装命令和 Release 链接
  换成占位版。

## 故意没改的

- VPN Gate 节点列表镜像（GeorgeXie2333 等）：那是节点数据来源，
  不是 miku-gate 上游，改了会断节点来源。
- Xray / sing-box 核心下载（CORE_ASSETS.json 里的 XTLS、SagerNet）：
  那是协议核心本身，不是 miku-gate 上游。
- README 里的赞助商、原项目致谢段落：属于署名，不是安装指向，
  留着原样；你要去掉赞助商段落时自行删那一段即可。
- 文件名、目录名：全部保持原样，没有重命名。

## 配套改动

- VMess 已移除：原生入站不再接受 VMess，界面下拉里没有 VMess，
  `vmess://` 导入和订阅转换都会报错；升级后残留的 VMess 入站
  不再生成运行配置、不再输出分享链接，需要在面板里删掉。
- Hysteria2 / TUIC：见 `docs/RELAY_HY2_TUIC.md`，只在自建 sing-box
  模式下创建，未绑出口默认走 `127.0.0.1:8500`，绑了出口走该隧道。
