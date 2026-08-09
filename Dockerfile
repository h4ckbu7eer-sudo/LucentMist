# LucentMist Dockerfile — 多阶段构建
# 使用: docker build -t lucentmist:0.9.0 .

# 国内网络构建可覆盖: docker build --build-arg NUGET_SOURCE=https://repo.huaweicloud.com/repository/nuget/v3/index.json
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json

# ============ 构建阶段 ============
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json
WORKDIR /src

# 复制项目文件
COPY LucentMist.slnx ./
COPY src ./src/

# 预置 Akka.Analyzers 完整缓存，避免容器内 NuGet 下载中断
COPY build/offline/akka.analyzers /root/.nuget/packages/akka.analyzers

# 复制全部源码（后续 restore 会覆盖任何误入的宿主机 obj）
COPY . .

# 还原依赖（只还原运行项目，测试由 CI 执行）
RUN cat > /tmp/NuGet.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="mirror" value="${NUGET_SOURCE}" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <config>
    <add key="httpRequestTimeout" value="30" />
  </config>
</configuration>
EOF
RUN for i in 1 2 3; do dotnet restore src/LucentMist.API/LucentMist.API.csproj --configfile /tmp/NuGet.config && break; sleep 3; done
RUN for i in 1 2 3; do dotnet restore src/LucentMist.Web/LucentMist.Web.csproj --configfile /tmp/NuGet.config && break; sleep 3; done
RUN for i in 1 2 3; do dotnet restore src/LucentMist.CLI/LucentMist.CLI.csproj --configfile /tmp/NuGet.config && break; sleep 3; done

# restore 后强制覆盖 Akka.Analyzers 完整缓存，避免残缺缓存导致 build 失败
RUN rm -rf /root/.nuget/packages/akka.analyzers \
 && cp -r build/offline/akka.analyzers /root/.nuget/packages/akka.analyzers

# 编译运行项目
RUN dotnet build src/LucentMist.API/LucentMist.API.csproj -c Release --no-restore
RUN dotnet build src/LucentMist.Web/LucentMist.Web.csproj -c Release --no-restore
RUN dotnet build src/LucentMist.CLI/LucentMist.CLI.csproj -c Release --no-restore

# 发布 API
RUN dotnet publish src/LucentMist.API -c Release -o /app/api --no-restore

# 发布 Web
RUN dotnet publish src/LucentMist.Web -c Release -o /app/web --no-restore

# 发布 CLI
RUN dotnet publish src/LucentMist.CLI -c Release -o /app/cli --no-restore

# ============ 运行阶段 ============
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# 安装 curl 用于健康检查（可选）
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制产物
COPY --from=build /app/api ./api
COPY --from=build /app/web ./web
COPY --from=build /app/cli ./cli

# 复制配置模板
COPY config/ ./config/

# 创建数据目录
RUN mkdir -p /app/data /app/logs && chown -R app:app /app

# 非 root 运行，降低容器被攻破后的提权风险
USER app

# 暴露 API + Web 端口
EXPOSE 5050 5051

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:5050/api/v1/health || exit 1

# 默认启动 API 服务；Web 服务通过 command 覆盖为 web/LucentMist.Web.dll 5051
CMD ["dotnet", "api/LucentMist.API.dll"]
