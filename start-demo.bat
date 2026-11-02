@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================================
echo   CodeGuard 演示环境
echo   API + Celery Worker + Redis + Vue3 控制台
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 python，请先激活虚拟环境或安装 Python 3.11+
  pause & exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 npm，请安装 Node.js 18+
  pause & exit /b 1
)

if "%REDIS_URL%"=="" set "REDIS_URL=redis://127.0.0.1:6380/0"
if "%CELERY_BROKER_URL%"=="" set "CELERY_BROKER_URL=redis://127.0.0.1:6380/1"
if "%CELERY_RESULT_BACKEND%"=="" set "CELERY_RESULT_BACKEND=redis://127.0.0.1:6380/2"
rem 6380 instead of 6379: 6379 is often taken by other local stacks
if "%REPORT_STORAGE_DIR%"=="" set "REPORT_STORAGE_DIR=data/reports"
if "%GITHUB_WEBHOOK_SECRET%"=="" set "GITHUB_WEBHOOK_SECRET=codeguard-demo-secret"

rem 可选：Semgrep 装在自定义目录时（如 pip install --target），指给扫描器
if "%CODEGUARD_SEMGREP_BIN%"=="" if exist "D:\codeguard-semgrep\bin\semgrep.exe" set "CODEGUARD_SEMGREP_BIN=D:\codeguard-semgrep\bin\semgrep.exe"

echo [1/5] 检查 Redis ...
docker inspect codeguard-redis >nul 2>nul
if errorlevel 1 (
  docker run -d --name codeguard-redis -p 6380:6379 redis:7-alpine >nul 2>nul
  if errorlevel 1 (
    echo       [警告] Redis 启动失败，实时链路将降级为轮询，Celery 任务不会执行
    echo       离线演示仍可用：python scripts\demo_scan.py --repo ^<本地仓库^>
  ) else (
    echo       Redis 容器已创建并启动
  )
) else (
  docker start codeguard-redis >nul 2>nul
  echo       Redis 容器已存在
)

echo [2/5] 启动 API (127.0.0.1:8000) ...
start "CodeGuard API" cmd /k "set REDIS_URL=%REDIS_URL%&& set CELERY_BROKER_URL=%CELERY_BROKER_URL%&& set CELERY_RESULT_BACKEND=%CELERY_RESULT_BACKEND%&& set REPORT_STORAGE_DIR=%REPORT_STORAGE_DIR%&& set GITHUB_WEBHOOK_SECRET=%GITHUB_WEBHOOK_SECRET%&& python -m uvicorn src.api.app:create_app --factory --host 127.0.0.1 --port 8000"

echo [3/5] 启动 Celery Worker ...
start "CodeGuard Worker" cmd /k "set REDIS_URL=%REDIS_URL%&& set CELERY_BROKER_URL=%CELERY_BROKER_URL%&& set CELERY_RESULT_BACKEND=%CELERY_RESULT_BACKEND%&& set REPORT_STORAGE_DIR=%REPORT_STORAGE_DIR%&& python -m celery -A src.tasks.celery_app worker -P solo -Q codeguard -l info"

echo [4/5] 等待 API 就绪 ...
set "READY=0"
for /l %%i in (1,1,40) do (
  if "!READY!"=="0" (
    powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } } catch {}; exit 1" >nul 2>nul
    if not errorlevel 1 (
      set "READY=1"
    ) else (
      timeout /t 1 /nobreak >nul
    )
  )
)
if "!READY!"=="0" (
  echo       [警告] API 20 秒内未就绪，请查看 "CodeGuard API" 窗口的报错
) else (
  echo       API 已就绪
)

echo [5/5] 启动控制台 (127.0.0.1:5173) ...
if not exist "frontend\node_modules" (
  echo       首次运行，安装前端依赖 ...
  pushd frontend
  call npm install --no-audit --no-fund
  popd
)
start "CodeGuard Console" cmd /k "cd frontend && npm run dev"

timeout /t 4 /nobreak >nul
start "" http://127.0.0.1:5173

echo.
echo ------------------------------------------------------------
echo  控制台   http://127.0.0.1:5173
echo  接口文档 http://127.0.0.1:8000/docs
echo.
echo  造一次 PR 触发（离线签名）：
echo    python scripts\emit_pr_webhook.py --repo encode/fastapi --pr 42 --secret %GITHUB_WEBHOOK_SECRET%
echo.
echo  跑一次真实离线扫描（写入控制台数据）：
echo    python scripts\demo_scan.py --repo C:\path\to\repo --name owner/repo --pr 42
echo.
echo  关闭：直接关掉三个命令行窗口，Redis 容器保持后台运行
echo ------------------------------------------------------------
echo.
pause
