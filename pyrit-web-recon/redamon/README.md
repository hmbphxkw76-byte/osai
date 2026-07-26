# RedAmon 源码目录

本目录用于存放 [RedAmon](https://github.com/samugit83/redamon) 源码，由 `docker-compose.integration.yml` 在一体化部署时构建使用。

## 使用方式

```powershell
cd d:\文档\GitHub\osai\pyrit-web-recon
git clone https://github.com/samugit83/redamon.git redamon
```

克隆完成后，运行：

```powershell
docker compose -f docker-compose.integration.yml --env-file .env.integration up -d
```

## 注意

- 本目录默认不包含源码，需手动克隆。
- 该目录下的内容由 RedAmon 官方仓库维护，不属于 `pyrit-web-recon` 核心代码。
