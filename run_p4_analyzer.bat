@echo off
REM Windows batch script to run the Perforce code analyzer

REM Check if changelist ID is provided
if "%~1"=="" (
    echo Usage: %0 ^<changelist_id^> [output_file]
    echo Example: %0 12345 report.md
    exit /b 1
)

set CHANGELIST_ID=%1
if "%~2"=="" (
    set OUTPUT_FILE=p4_analysis_report.md
) else (
    set OUTPUT_FILE=%2
)

REM Run the analyzer
python p4_code_analyzer.py %CHANGELIST_ID% --output %OUTPUT_FILE%

if %ERRORLEVEL% EQU 0 (
    echo Analysis completed successfully.
    
    REM Check if the output file exists before trying to open it
    if exist %OUTPUT_FILE% (
        echo Opening report: %OUTPUT_FILE%
        start %OUTPUT_FILE%
    ) else (
        echo WARNING: Report file %OUTPUT_FILE% was not created.
    )
) else (
    echo Analysis failed. See error messages above.
    exit /b 1
)