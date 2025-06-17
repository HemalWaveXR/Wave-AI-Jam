import subprocess
import sys

print(f"Python version: {sys.version}")

# Try to create a simple output file
try:
    with open('test_output.md', 'w') as f:
        f.write("# Test Report\n\nThis is a test report file.\n")
    print("Successfully created test_output.md")
except Exception as e:
    print(f"Error creating file: {e}")

# Try to run p4 info
try:
    result = subprocess.run(["p4", "info"], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True)
    
    if result.returncode == 0:
        print("p4 info executed successfully")
    else:
        print(f"p4 info failed: {result.stderr}")
except Exception as e:
    print(f"Error running p4: {e}")

print("Test completed")