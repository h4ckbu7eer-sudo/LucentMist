# LucentMist Dockerfile — 多阶段构建
# 使用: docker build -t lucentmist:0.5.0 .

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
RUN dotnet test -c Release --no-restore --verbosity normal --filter "Category!=External"

# 发布 API
RUN dotnet publish src/LucentMist.API -c Release -o /app/api --no-restore

# 发布 CLI
RUN dotnet publish src/LucentMist.CLI -c Release -o /app/cli --no-restore

# 发布 Web
RUN dotnet publish src/LucentMist.Web -c Release -o /app/web --no-restore

# ============ 运行阶段 ============
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# 安装 curl 用于健康检查（可选）
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制产物
COPY --from=build /app/api ./api
COPY --from=build /app/cli ./cli
COPY --from=build /app/web ./web

# 复制配置模板
COPY config/ ./config/

# 创建数据目录
RUN mkdir -p /app/data /app/logs

# 暴露 API + Web 端口
EXPOSE 5050 5051

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:5050/api/v1/health || exit 1

# 默认启动 API 服务
ENTRYPOINT ["dotnet", "api/LucentMist.API.dll"]
