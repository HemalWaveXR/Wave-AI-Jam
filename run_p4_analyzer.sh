#!/bin/bash
# Script to run the Perforce code analyzer

# Check if changelist ID is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <changelist_id> [output_file]"
    echo "Example: $0 12345 report.md"
    exit 1
fi

CHANGELIST_ID=$1
OUTPUT_FILE=${2:-"p4_analysis_report.md"}

# Run the analyzer
python3 p4_code_analyzer.py $CHANGELIST_ID --output $OUTPUT_FILE

# Open the report if successful
if [ $? -eq 0 ]; then
    echo "Analysis completed successfully."
    
    # Try to open the report with an appropriate viewer
    if command -v xdg-open &> /dev/null; then
        xdg-open $OUTPUT_FILE  # Linux
    elif command -v open &> /dev/null; then
        open $OUTPUT_FILE  # macOS
    elif command -v start &> /dev/null; then
        start $OUTPUT_FILE  # Windows
    else
        echo "Report generated at: $OUTPUT_FILE"
    fi
else
    echo "Analysis failed. See error messages above."
    exit 1
fi