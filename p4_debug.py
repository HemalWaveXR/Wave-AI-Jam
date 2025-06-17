import os
import sys
import logging
import platform

# Configure logging to console and file
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("p4_debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("p4_debug")

# Log system info
logger.info("System: %s %s", platform.system(), platform.release())
logger.info("Python version: %s", sys.version)
logger.info("Current directory: %s", os.getcwd())
logger.info("Current user: %s", os.getenv('USERNAME'))

# Check if p4 is available
try:
    import subprocess
    logger.info("Checking for p4 executable...")
    result = subprocess.run(["p4", "info"], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True)
    
    if result.returncode == 0:
        logger.info("p4 is available:")
        for line in result.stdout.splitlines()[:5]:  # Log first 5 lines
            logger.info("  %s", line.strip())
    else:
        logger.error("p4 command failed with error: %s", result.stderr)
except Exception as e:
    logger.exception("Error checking for p4: %s", str(e))

# Check file write permissions
try:
    logger.info("Testing file write permissions...")
    test_file = "test_write_permission.txt"
    with open(test_file, "w") as f:
        f.write("Test write permissions")
    logger.info("Successfully wrote to test file")
    os.remove(test_file)
    logger.info("Successfully removed test file")
except Exception as e:
    logger.exception("Error testing file permissions: %s", str(e))

logger.info("Debug script completed")