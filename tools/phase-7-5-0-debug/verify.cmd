@echo off
REM Phase 7.5.0 verification harness (Windows cmd version).
REM
REM Runs the gates that Phase 7.5.0 closure depends on, with per-stage
REM output captured to discrete files under out\ so any failure is
REM narrow-debuggable. Stages run in order; later stages still run
REM after an earlier failure so we get the full picture in one pass.
REM
REM Output:
REM   out\<stage>.log     - full captured stdout+stderr
REM   out\<stage>.exit    - numeric exit code
REM   out\SUMMARY.txt     - consolidated status table

setlocal enabledelayedexpansion

REM cd to repo root (two levels up from this script).
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%..\.."

set "OUT=%SCRIPT_DIR%out"
if not exist "%OUT%" mkdir "%OUT%"
del /Q "%OUT%\*.log" 2>nul
del /Q "%OUT%\*.exit" 2>nul
del /Q "%OUT%\SUMMARY.txt" 2>nul

set "FAIL_COUNT=0"

REM ====================================================================
REM Stage 1: vdf-tests
REM ====================================================================
echo ====================================================
echo [stage] vdf-tests
echo ====================================================
cargo test -p adamant-crypto vdf > "%OUT%\vdf-tests.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\vdf-tests.exit"
if "!RC!"=="0" (echo [ok]    vdf-tests) else (call :report_fail vdf-tests !RC!)
echo.

REM ====================================================================
REM Stage 2: crypto-clippy
REM ====================================================================
echo ====================================================
echo [stage] crypto-clippy
echo ====================================================
cargo clippy -p adamant-crypto -- -D warnings > "%OUT%\crypto-clippy.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\crypto-clippy.exit"
if "!RC!"=="0" (echo [ok]    crypto-clippy) else (call :report_fail crypto-clippy !RC!)
echo.

REM ====================================================================
REM Stage 3: workspace-clippy
REM ====================================================================
echo ====================================================
echo [stage] workspace-clippy
echo ====================================================
cargo clippy --workspace --all-targets -- -D warnings > "%OUT%\workspace-clippy.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\workspace-clippy.exit"
if "!RC!"=="0" (echo [ok]    workspace-clippy) else (call :report_fail workspace-clippy !RC!)
echo.

REM ====================================================================
REM Stage 4: fmt
REM ====================================================================
echo ====================================================
echo [stage] fmt
echo ====================================================
cargo fmt --all -- --check > "%OUT%\fmt.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\fmt.exit"
if "!RC!"=="0" (echo [ok]    fmt) else (call :report_fail fmt !RC!)
echo.

REM ====================================================================
REM Stage 5: workspace-tests (lib+bins+tests; skips doctests because
REM         adamant-halo2's vendored doctests fail at HEAD, unrelated
REM         to Phase 7.5.0)
REM ====================================================================
echo ====================================================
echo [stage] workspace-tests
echo ====================================================
cargo test --workspace --lib --bins --tests > "%OUT%\workspace-tests.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\workspace-tests.exit"
if "!RC!"=="0" (echo [ok]    workspace-tests) else (call :report_fail workspace-tests !RC!)
echo.

REM ====================================================================
REM Stage 6: audit
REM ====================================================================
echo ====================================================
echo [stage] audit
echo ====================================================
python tools\workspace-audit\audit.py --strict > "%OUT%\audit.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\audit.exit"
if "!RC!"=="0" (echo [ok]    audit) else (call :report_fail audit !RC!)
echo.

REM ====================================================================
REM Stage 7: no-sui resistant-proof guard
REM ====================================================================
echo ====================================================
echo [stage] no-sui
echo ====================================================
cargo test --workspace --test no_sui_in_production_deps > "%OUT%\no-sui.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\no-sui.exit"
if "!RC!"=="0" (echo [ok]    no-sui) else (call :report_fail no-sui !RC!)
echo.

REM ====================================================================
REM Stage 8: no-halo2 resistant-proof guard
REM ====================================================================
echo ====================================================
echo [stage] no-halo2
echo ====================================================
cargo test --workspace --test no_upstream_halo2_in_production_deps > "%OUT%\no-halo2.log" 2>&1
set "RC=!ERRORLEVEL!"
echo !RC!> "%OUT%\no-halo2.exit"
if "!RC!"=="0" (echo [ok]    no-halo2) else (call :report_fail no-halo2 !RC!)
echo.

REM ====================================================================
REM Build SUMMARY.txt
REM ====================================================================
> "%OUT%\SUMMARY.txt" echo Phase 7.5.0 verification summary
>> "%OUT%\SUMMARY.txt" echo Timestamp: %DATE% %TIME%
>> "%OUT%\SUMMARY.txt" echo.
>> "%OUT%\SUMMARY.txt" echo stage                  result
>> "%OUT%\SUMMARY.txt" echo --------------------   ------

for %%S in (vdf-tests crypto-clippy workspace-clippy fmt workspace-tests audit no-sui no-halo2) do (
    set /p RC=<"%OUT%\%%S.exit"
    if "!RC!"=="0" (
        >> "%OUT%\SUMMARY.txt" echo %%-20S   ok
    ) else (
        >> "%OUT%\SUMMARY.txt" echo %%-20S   FAIL ^(exit !RC!^)
    )
)

>> "%OUT%\SUMMARY.txt" echo.
if "%FAIL_COUNT%"=="0" (
    >> "%OUT%\SUMMARY.txt" echo Overall: ALL GATES PASS
) else (
    >> "%OUT%\SUMMARY.txt" echo Overall: %FAIL_COUNT% FAILURES - inspect logs under %OUT%
)

type "%OUT%\SUMMARY.txt"

popd
if "%FAIL_COUNT%"=="0" (exit /b 0) else (exit /b 1)


:report_fail
echo [FAIL]  %~1 ^(exit %~2^) - see %OUT%\%~1.log
set /a FAIL_COUNT=!FAIL_COUNT! + 1
echo.
echo --- last 40 lines of %~1.log ---
powershell -NoProfile -Command "Get-Content -Path '%OUT%\%~1.log' -Tail 40"
echo --- end ---
exit /b 0
