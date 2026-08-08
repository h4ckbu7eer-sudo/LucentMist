# LucentMist Dockerfile — 多阶段构建
# 使用: docker build -t lucentmist:0.1.0 .

# ============ 构建阶段 ============
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# 复制项目文件
COPY LucentMist.slnx ./
COPY src ./src/
COPY tests ./tests/

# 还原依赖
RUN dotnet restore

# 复制源码
COPY . .

# 编译 + 测试
RUN dotnet build -c Release --no-restore
RUN dotnet test -c Release --no-restore --verbosity normal

# 发布 API（自包含）
RUN dotnet publish src/LucentMist.API -c Release -o /app/api --no-restore

# 发布 CLI（自包含）
RUN dotnet publish src/LucentMist.CLI -c Release -o /app/cli --no-restore

# ============ 运行阶段 ============
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
WORKDIR /app

# 安装 curl 用于健康检查（可选）
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制产物
COPY --from=build /app/api ./api
COPY --from=build /app/cli ./cli

# 复制配置模板
COPY config/ ./config/

# 创建数据目录
RUN mkdir -p /app/data /app/logs

# 暴露 API 端口
EXPOSE 5050

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:5050/api/v1/health || exit 1

# 默认启动 API 服务
ENTRYPOINT ["dotnet", "api/LucentMist.API.dll"]
