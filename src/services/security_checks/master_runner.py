import importlib
import logging

logger = logging.getLogger(__name__)

def run_all(target_url):
    results = {}
    
    # Loop through checks 2 to 28
    for i in range(2, 29):
        try:
            # Dynamic import: src.services.security_checks.check2, check3, etc.
            module_name = f"src.services.security_checks.check{i}"
            module = importlib.import_module(module_name)
            
            # Execute the standard run_check function in each module
            results[str(i)] = module.run_check(target_url)
            
        except ModuleNotFoundError:
            logger.warning(f"Check module check{i}.py not found. Skipping.")
            results[str(i)] = {"compliance": "Y", "remark": "Check module missing.", "severity": "info"}
        except Exception as e:
            logger.error(f"Error executing check{i}: {str(e)}")
            results[str(i)] = {"compliance": "N", "remark": f"Execution error: {str(e)}", "severity": "high"}
            
    return results