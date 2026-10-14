# Firewall Policy Tools

基于 Web 的防火墙策略管理工具，当前支持 Cisco ASA、Palo Alto、Fortinet 和 Huawei 配置导入解析、统一查询、对象查看、风险分析、策略申请和审计记录。

## 功能概览

- 多厂商配置导入：Cisco ASA、Palo Alto、Fortinet、Huawei
- 多设备树型目录：按厂商、设备分类查看
- 策略查询：源、目的、端口/服务、应用、用户、区域/ACL、动作、关键字
- 对象查询：地址对象、服务对象、对象组
- 策略可视化：路径分析、矩阵视图、拓扑视图、依赖关系图、规则顺序视图
- 策略分析：冲突、重复、遮挡/永不命中、过宽策略、高危端口/应用、跨区域风险
- 变更预检查：新增策略前检查冲突、重叠、互斥和推荐插入位置
- 本地持久化：SQLite 数据库存储导入结果和变更记录

## Docker 安装

从 GitHub 拉取代码：

```bash
git clone https://github.com/boxie283555/FireWall-Policy-tools.git FireWall-Policy-tools
cd FireWall-Policy-tools
```

启动服务：

```bash
docker compose up -d --build
```

访问：

```text
http://192.168.20.169:8080
```

查看日志：

```bash
docker compose logs -f
```

停止服务：

```bash
docker compose down
```

数据保存在本地 `data/` 目录，默认不会提交到 Git。

## 本机安装

适合在自己的电脑上运行和调试。以下命令适用于 macOS / Linux 终端。

### 1. 安装前准备

确认本机已经安装：

- Python 3.10 或以上版本
- Git

检查命令：

```bash
python3 --version
git --version
```

### 2. 下载代码

```bash
git clone https://github.com/boxie283555/FireWall-Policy-tools.git
cd FireWall-Policy-tools
```

### 3. 创建 Python 虚拟环境

```bash
python3 -m venv .venv
source .venv/bin/activate
```

激活成功后，终端前面通常会出现 `(.venv)`。

### 4. 安装依赖

```bash
pip install -r requirements.txt
```

### 5. 启动服务

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

访问：

```text
http://127.0.0.1:8080
```

如果希望同一局域网里的其他机器也能访问，把启动命令改成：

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

然后使用本机 IP 访问，例如：

```text
http://本机IP:8080
```

### 6. 停止服务

在运行 `uvicorn` 的终端窗口按：

```text
Ctrl + C
```

### 7. 下次启动

进入项目目录，激活虚拟环境后启动：

```bash
cd FireWall-Policy-tools
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

### 8. 更新代码

```bash
cd FireWall-Policy-tools
git pull
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

导入后的数据保存在 `data/` 目录里，更新代码不会自动删除。

## 部署到 192.168.20.169

在 `192.168.20.169` 上安装 Docker 和 Docker Compose 后，推荐直接从 GitHub 拉取并启动：

```bash
ssh 192.168.20.169
git clone https://github.com/boxie283555/FireWall-Policy-tools.git /opt/firewall-policy-tools
cd /opt/firewall-policy-tools
docker compose up -d --build
```

如服务器已经有旧版本，更新方式：

```bash
cd /opt/firewall-policy-tools
git pull
docker compose up -d --build
```

服务默认监听 `8080` 端口。

也可以从当前机器用脚本上传部署：

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh 192.168.20.169 /opt/firewall-policy-tools
```

## 使用方式

1. 打开 `http://192.168.20.169:8080`
2. 进入 `Import Config`
3. 选择厂商和设备名，上传或粘贴配置
4. 进入 `Access Rules` 查询策略
5. 进入 `Objects` 查询对象
6. 进入 `Path / Topology` 查看路径、矩阵、拓扑、依赖关系和规则顺序
7. 进入 `Risk Findings` 查看风险分析结果
8. 进入 `Change Requests` 做新增策略预检查

## GitHub 推送

首次推送到 GitHub：

```bash
git remote add origin https://github.com/boxie283555/FireWall-Policy-tools.git
git branch -M main
git push -u origin main
```
