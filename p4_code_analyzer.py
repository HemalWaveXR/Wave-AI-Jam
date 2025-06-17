#!/usr/bin/env python3
"""
Perforce Changelist Code Analyzer

This tool analyzes files in a specific Perforce changelist to detect potential
null pointer exceptions, errors, and memory leaks.
"""

import os
import sys
import re
import argparse
import subprocess
import logging
from enum import Enum
from typing import List, Dict, Tuple, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class IssueSeverity(Enum):
    """Severity levels for detected issues"""
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IssueType(Enum):
    """Types of issues that can be detected"""
    NULL_POINTER = "NULL_POINTER"
    MEMORY_LEAK = "MEMORY_LEAK"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    UNINITIALIZED_VARIABLE = "UNINITIALIZED_VARIABLE"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    DIVISION_BY_ZERO = "DIVISION_BY_ZERO"
    OTHER = "OTHER"

class CodeIssue:
    """Represents a detected issue in the code"""
    
    def __init__(self, 
                 file_path: str, 
                 line_number: int, 
                 issue_type: IssueType, 
                 severity: IssueSeverity, 
                 message: str, 
                 code_context: str):
        self.file_path = file_path
        self.line_number = line_number
        self.issue_type = issue_type
        self.severity = severity
        self.message = message
        self.code_context = code_context
    
    def __str__(self) -> str:
        return (f"{self.file_path}:{self.line_number} [{self.severity.value}] {self.issue_type.value}: "
                f"{self.message}\nCode: {self.code_context}")

class PerforceClient:
    """Handles interaction with the Perforce server"""
    
    def __init__(self, p4_path: str = "p4"):
        """Initialize the Perforce client with the path to p4 executable"""
        self.p4_path = p4_path
        self._check_p4_available()
        
    def _check_p4_available(self):
        """Check if p4 command is available"""
        try:
            result = subprocess.run([self.p4_path, "info"], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    text=True,
                                    check=True)
            logger.debug(f"Perforce client detected: {result.stdout.strip()}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Perforce client not found or not working: {str(e)}")
            sys.exit(1)
    
    def get_changelist_files(self, changelist_id: int) -> List[Dict]:
        """Get the list of files in the specified changelist"""
        try:
            result = subprocess.run(
                [self.p4_path, "describe", "-s", str(changelist_id)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            files = []
            file_pattern = re.compile(r'^\.\.\. (.+)#\d+ (add|edit|delete|integrate|branch)')
            
            for line in result.stdout.splitlines():
                match = file_pattern.match(line.strip())
                if match:
                    file_path = match.group(1)
                    action = match.group(2)
                    
                    # Skip files being deleted
                    if action == "delete":
                        continue
                        
                    files.append({
                        "path": file_path,
                        "action": action
                    })
            
            return files
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error retrieving changelist {changelist_id}: {str(e)}")
            if e.stderr:
                logger.error(f"P4 error: {e.stderr}")
            sys.exit(1)
    
    def get_file_content(self, file_path: str, changelist_id: int) -> Optional[str]:
        """Get the content of a file in the specified changelist"""
        try:
            result = subprocess.run(
                [self.p4_path, "print", f"{file_path}@={changelist_id}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning(f"Could not retrieve {file_path} from changelist {changelist_id}: {result.stderr}")
                return None
                
            # Remove the file header that p4 print adds
            lines = result.stdout.splitlines()
            content_start = 0
            for i, line in enumerate(lines):
                if line.startswith(file_path):
                    content_start = i + 1
                    break
                    
            return "\n".join(lines[content_start:])
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error retrieving file {file_path}: {str(e)}")
            return None

class CodeAnalyzer:
    """Base class for language-specific code analyzers"""
    
    def get_language(self) -> str:
        """Get the programming language this analyzer handles"""
        raise NotImplementedError
    
    def can_analyze(self, file_path: str) -> bool:
        """Check if this analyzer can handle the given file"""
        raise NotImplementedError
        
    def analyze(self, file_path: str, content: str) -> List[CodeIssue]:
        """Analyze the code content and return issues found"""
        raise NotImplementedError

class CppAnalyzer(CodeAnalyzer):
    """Analyzer for C/C++ code"""
    
    def get_language(self) -> str:
        return "C/C++"
    
    def can_analyze(self, file_path: str) -> bool:
        extensions = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hxx'}
        ext = os.path.splitext(file_path)[1].lower()
        return ext in extensions
    
    def analyze(self, file_path: str, content: str) -> List[CodeIssue]:
        issues = []
        
        # Split content into lines for analysis and preserve original line numbers
        lines = content.splitlines()
        
        # Patterns for detecting potential issues
        null_ptr_patterns = [
            # Dereferencing after null check
            (r'if\s*\(\s*(.*?)\s*==\s*nullptr\s*\)(.*?)(?:\1->|\*\s*\1)', 
             IssueType.NULL_POINTER, IssueSeverity.HIGH,
             "Potential null pointer dereference after null check"),
            
            # Dereferencing possibly null pointers
            (r'(\w+)\s*=\s*nullptr;.*?\1->', 
             IssueType.NULL_POINTER, IssueSeverity.HIGH,
             "Dereferencing after explicit nullptr assignment"),
             
            # Division by zero
            (r'\/\s*(?:0|0\.0|0\.0f|\w+\s*==\s*0)', 
             IssueType.DIVISION_BY_ZERO, IssueSeverity.CRITICAL,
             "Potential division by zero"),
        ]
        
        memory_leak_patterns = [
            # Memory allocated but not stored or freed
            (r'(?:new\s+\w+(?:\s*\[\s*\w+\s*\])?|malloc\s*\(.*?\)|calloc\s*\(.*?\))((?:(?!delete|free).)*?;)', 
             IssueType.MEMORY_LEAK, IssueSeverity.MEDIUM,
             "Potential memory leak: allocated memory not stored in a variable"),
            
            # Resource acquisition without release pattern
            (r'(\w+)\s*=\s*(?:fopen|CreateFile|open)\s*\(.*?(?!\1.+?(?:fclose|CloseHandle|close))', 
             IssueType.RESOURCE_LEAK, IssueSeverity.MEDIUM,
             "Potential resource leak: resource might not be properly closed"),
        ]
        
        uninitialized_patterns = [
            # Variable declared but not initialized
            (r'(?:int|float|double|char|bool|long)\s+(\w+);(?!\s*\1\s*=)', 
             IssueType.UNINITIALIZED_VARIABLE, IssueSeverity.LOW,
             "Variable declared but not initialized"),
        ]
        
        buffer_overflow_patterns = [
            # Unsafe string functions
            (r'(?:strcpy|strcat|sprintf|gets)\s*\(', 
             IssueType.BUFFER_OVERFLOW, IssueSeverity.HIGH,
             "Using unsafe string function (potential buffer overflow)"),
        ]
        
        # Combine all patterns
        all_patterns = null_ptr_patterns + memory_leak_patterns + uninitialized_patterns + buffer_overflow_patterns
        
        # Search for patterns in multiple-line windows to catch issues spanning lines
        window_size = 5
        for i in range(len(lines)):
            line_window = "\n".join(lines[max(0, i-window_size):min(len(lines), i+window_size+1)])
            current_line = lines[i] if i < len(lines) else ""
            
            for pattern, issue_type, severity, message in all_patterns:
                if re.search(pattern, current_line):
                    # Context is current line plus a few surrounding lines for context
                    context_start = max(0, i-2)
                    context_end = min(len(lines), i+3)
                    code_context = "\n".join([
                        f"{j+1}: {lines[j]}" for j in range(context_start, context_end)
                    ])
                    
                    issue = CodeIssue(
                        file_path=file_path,
                        line_number=i+1,
                        issue_type=issue_type,
                        severity=severity,
                        message=message,
                        code_context=code_context
                    )
                    issues.append(issue)
        
        return issues

class CSharpAnalyzer(CodeAnalyzer):
    """Analyzer for C# code"""
    
    def get_language(self) -> str:
        return "C#"
    
    def can_analyze(self, file_path: str) -> bool:
        extensions = {'.cs'}
        ext = os.path.splitext(file_path)[1].lower()
        return ext in extensions
    
    def analyze(self, file_path: str, content: str) -> List[CodeIssue]:
        issues = []
        
        # Split content into lines for analysis
        lines = content.splitlines()
        
        # Patterns for detecting potential issues
        null_ptr_patterns = [
            # Dereferencing after null check
            (r'if\s*\(\s*(.*?)\s*==\s*null\s*\)(.*?)(?:\1\.|\s*\1\[)', 
             IssueType.NULL_POINTER, IssueSeverity.HIGH,
             "Potential null reference exception after null check"),
            
            # Null reference
            (r'(\w+)\s*=\s*null;.*?\1\.', 
             IssueType.NULL_POINTER, IssueSeverity.HIGH,
             "Accessing member after explicit null assignment"),
             
            # Forgetting null check before using
            (r'(\w+)\s*=\s*.*?(?:GetComponent|Find|FirstOrDefault).*?;\s*(?!\s*if\s*\(\s*\1\s*!=\s*null\))\s*\1\.', 
             IssueType.NULL_POINTER, IssueSeverity.MEDIUM,
             "Using result of method that might return null without null check"),
        ]
        
        resource_leak_patterns = [
            # IDisposable not in using statement
            (r'new\s+(?:StreamReader|StreamWriter|FileStream|SqlConnection).*?(?!using|\.Dispose\(\)|\.Close\(\))', 
             IssueType.RESOURCE_LEAK, IssueSeverity.MEDIUM,
             "IDisposable resource not in using statement or explicitly disposed"),
        ]
        
        # Combine all patterns
        all_patterns = null_ptr_patterns + resource_leak_patterns
        
        # Search for patterns in multiple-line windows to catch issues spanning lines
        window_size = 5
        for i in range(len(lines)):
            line_window = "\n".join(lines[max(0, i-window_size):min(len(lines), i+window_size+1)])
            current_line = lines[i] if i < len(lines) else ""
            
            for pattern, issue_type, severity, message in all_patterns:
                if re.search(pattern, current_line):
                    # Context is current line plus a few surrounding lines for context
                    context_start = max(0, i-2)
                    context_end = min(len(lines), i+3)
                    code_context = "\n".join([
                        f"{j+1}: {lines[j]}" for j in range(context_start, context_end)
                    ])
                    
                    issue = CodeIssue(
                        file_path=file_path,
                        line_number=i+1,
                        issue_type=issue_type,
                        severity=severity,
                        message=message,
                        code_context=code_context
                    )
                    issues.append(issue)
        
        return issues

class PerforceCodeAnalyzer:
    """Main class for analyzing Perforce changelists"""
    
    def __init__(self):
        self.p4_client = PerforceClient()
        self.analyzers = [
            CppAnalyzer(),
            CSharpAnalyzer(),
            # Add more analyzers here as needed
        ]
        
    def get_analyzer_for_file(self, file_path: str) -> Optional[CodeAnalyzer]:
        """Get the appropriate analyzer for the given file"""
        for analyzer in self.analyzers:
            if analyzer.can_analyze(file_path):
                return analyzer
        return None
        
    def analyze_changelist(self, changelist_id: int) -> List[CodeIssue]:
        """Analyze all files in the specified changelist"""
        logger.info(f"Analyzing changelist {changelist_id}...")
        
        issues = []
        files = self.p4_client.get_changelist_files(changelist_id)
        logger.info(f"Found {len(files)} files in changelist {changelist_id}")
        
        for file_info in files:
            file_path = file_info["path"]
            logger.info(f"Processing {file_path}...")
            
            analyzer = self.get_analyzer_for_file(file_path)
            if analyzer is None:
                logger.info(f"No analyzer available for {file_path}, skipping")
                continue
                
            content = self.p4_client.get_file_content(file_path, changelist_id)
            if content is None:
                logger.warning(f"Could not retrieve content for {file_path}, skipping")
                continue
                
            logger.info(f"Analyzing {file_path} using {analyzer.get_language()} analyzer")
            file_issues = analyzer.analyze(file_path, content)
            issues.extend(file_issues)
            
            logger.info(f"Found {len(file_issues)} issues in {file_path}")
            
        return issues
        
    def generate_report(self, issues: List[CodeIssue]) -> str:
        """Generate a report of the issues found"""
        if not issues:
            return "No issues found."
            
        # Group issues by severity
        issues_by_severity = {
            IssueSeverity.CRITICAL: [],
            IssueSeverity.HIGH: [],
            IssueSeverity.MEDIUM: [],
            IssueSeverity.LOW: [],
        }
        
        for issue in issues:
            issues_by_severity[issue.severity].append(issue)
            
        # Build report
        report = []
        report.append("# Code Analysis Report\n")
        report.append(f"Total issues found: {len(issues)}\n")
        
        for severity in IssueSeverity:
            severity_issues = issues_by_severity[severity]
            if not severity_issues:
                continue
                
            report.append(f"\n## {severity.value} Severity Issues ({len(severity_issues)})\n")
            
            # Group by issue type
            issues_by_type = {}
            for issue in severity_issues:
                if issue.issue_type not in issues_by_type:
                    issues_by_type[issue.issue_type] = []
                issues_by_type[issue.issue_type].append(issue)
                
            # Add issues grouped by type
            for issue_type, type_issues in issues_by_type.items():
                report.append(f"\n### {issue_type.value} ({len(type_issues)})\n")
                
                for i, issue in enumerate(type_issues, 1):
                    report.append(f"\n#### {i}. {issue.file_path}:{issue.line_number}\n")
                    report.append(f"**Message:** {issue.message}\n")
                    report.append("**Code Context:**\n```\n")
                    report.append(issue.code_context)
                    report.append("\n```\n")
        
        return "\n".join(report)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Analyze files in a specific Perforce changelist for null pointers, errors, and memory leaks."
    )
    parser.add_argument(
        "changelist_id",
        type=int,
        help="ID of the Perforce changelist to analyze"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for the generated report",
        default="p4_analysis_report.md"
    )
    parser.add_argument(
        "--p4-path",
        help="Path to the p4 executable",
        default="p4"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    analyzer = PerforceCodeAnalyzer()
    try:
        issues = analyzer.analyze_changelist(args.changelist_id)
        report = analyzer.generate_report(issues)
        
        # Write report to file
        with open(args.output, 'w') as f:
            f.write(report)
            
        logger.info(f"Analysis complete. Found {len(issues)} issues.")
        logger.info(f"Report written to {args.output}")
        
        # Print summary to console
        severity_count = {s.value: 0 for s in IssueSeverity}
        for issue in issues:
            severity_count[issue.severity.value] += 1
            
        for severity, count in severity_count.items():
            if count > 0:
                logger.info(f"{severity} issues: {count}")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())