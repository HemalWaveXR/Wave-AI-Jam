@echo off
SETLOCAL EnableDelayedExpansion

REM Windows batch script to run the Perforce code analyzer

REM Check if changelist ID is provided
if "%~1"=="" (
    echo Usage: %0 ^<changelist_id^> [output_file]
    echo Example: %0 12345 report.md
    exit /b 1
)

set CHANGELIST_ID=%1
if "%~2"=="" (
    set OUTPUT_FILE=%CD%\p4_analysis_report.md
) else (
    set OUTPUT_FILE=%~2
)

echo.
echo ====================================
echo Perforce Code Analyzer
echo ====================================
echo Analyzing changelist: %CHANGELIST_ID%
echo Output report: %OUTPUT_FILE%
echo.

REM Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Please install Python 3.6 or later.
    exit /b 1
)

REM Check if p4 is available
p4 -V >nul 2>&1
set P4_AVAILABLE=%ERRORLEVEL%

if %P4_AVAILABLE% NEQ 0 (
    echo WARNING: P4 command not found in PATH.
    echo Searching for Perforce in common locations...
    
    REM Try to find p4 in common installation directories
    set "P4_PATHS="
    set "P4_PATHS=!P4_PATHS! %ProgramFiles%\Perforce\p4.exe"
    set "P4_PATHS=!P4_PATHS! %ProgramFiles(x86)%\Perforce\p4.exe"
    set "P4_PATHS=!P4_PATHS! %APPDATA%\Perforce\p4.exe"
    set "P4_PATHS=!P4_PATHS! %LOCALAPPDATA%\Perforce\p4.exe"
    set "P4_PATHS=!P4_PATHS! C:\Perforce\p4.exe"
    
    set "P4_PATH="
    for %%p in (!P4_PATHS!) do (
        if exist "%%p" (
            set "P4_PATH=%%p"
            echo Found P4 at: !P4_PATH!
            goto :p4_found
        )
    )
    
    :p4_not_found
    echo ERROR: Could not find p4 executable.
    echo Please install Perforce client from: https://www.perforce.com/downloads/helix-command-line-client-p4
    echo Or provide the full path using --p4-path option.
    exit /b 1
    
    :p4_found
    echo Running with custom P4 path: !P4_PATH!
    
    REM Run the analyzer with custom p4 path
    python p4_code_analyzer.py %CHANGELIST_ID% --output "%OUTPUT_FILE%" --p4-path "!P4_PATH!" -v
) else (
    REM Run the analyzer with default p4 in PATH
    python p4_code_analyzer.py %CHANGELIST_ID% --output "%OUTPUT_FILE%" -v
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Analysis completed successfully.
    
    REM Check if the output file exists before trying to open it
    if exist "%OUTPUT_FILE%" (
        echo Opening report: %OUTPUT_FILE%
        start "" "%OUTPUT_FILE%"
    ) else (
        echo WARNING: Report file %OUTPUT_FILE% was not created.
        echo Check p4_analyzer.log for details.
    )
) else (
    echo.
    echo Analysis failed with error code %ERRORLEVEL%.
    echo See p4_analyzer.log for detailed error information.
    exit /b 1
)

ENDLOCAL