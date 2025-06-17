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
import platform
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
            # Print system information for debugging
            logger.info(f"System: {platform.system()} {platform.release()}")
            logger.info(f"Current directory: {os.getcwd()}")
            logger.info(f"Looking for p4 at: {self.p4_path}")
            
            # Check if file exists
            if not os.path.isfile(self.p4_path) and "/" in self.p4_path:
                logger.error(f"P4 executable not found at specified path: {self.p4_path}")
                logger.info("Please install Perforce client or provide the correct path with --p4-path")
                sys.exit(1)
                
            # Try to run p4 command
            cmd = [self.p4_path, "info"]
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Error running p4 info: {result.stderr}")
                logger.info("Please check your Perforce configuration and connectivity")
                sys.exit(1)
                
            logger.info(f"Perforce client detected: {result.stdout.splitlines()[0].strip()}")
            
        except FileNotFoundError as e:
            logger.error(f"Perforce client not found: {str(e)}")
            logger.info("Make sure p4 is installed and available in your PATH")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error checking p4: {str(e)}")
            sys.exit(1)
    
    def get_changelist_files(self, changelist_id: int) -> List[Dict]:
        """Get the list of files in the specified changelist"""
        try:
            cmd = [self.p4_path, "describe", "-s", str(changelist_id)]
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Error retrieving changelist {changelist_id}: {result.stderr}")
                logger.info("Please check that the changelist exists and you have access to it")
                sys.exit(1)
            
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
            
            if not files:
                logger.warning(f"No files found in changelist {changelist_id} or pattern matching failed")
                logger.info(f"Raw output from p4 describe: {result.stdout}")
            
            return files
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error retrieving changelist {changelist_id}: {str(e)}")
            if hasattr(e, 'stderr') and e.stderr:
                logger.error(f"P4 error: {e.stderr}")
            sys.exit(1)
    
    def get_file_content(self, file_path: str, changelist_id: int) -> Optional[str]:
        """Get the content of a file in the specified changelist"""
        try:
            cmd = [self.p4_path, "print", f"{file_path}@={changelist_id}"]
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
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

# [The rest of the code remains the same]