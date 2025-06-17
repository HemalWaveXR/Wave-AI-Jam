# Perforce Changelist Code Analyzer

A tool to analyze files in a specific Perforce changelist to detect potential null pointer exceptions, errors, and memory leaks.

## Features

- Connects to a Perforce server and retrieves files from a specified changelist
- Supports multiple programming languages (C++, C#)
- Performs static code analysis on the retrieved files
- Generates a report of potential issues found, categorized by severity
- Provides line numbers and code context for each detected issue
- Focuses specifically on detecting:
  - Null pointer dereferences
  - Memory leaks
  - Resource leaks
  - Uninitialized variables
  - Buffer overflows
  - Division by zero errors

## Prerequisites

- Python 3.6 or higher
- Perforce command-line client (p4) accessible in your PATH

## Installation

1. Clone this repository: