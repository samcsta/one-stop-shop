// Common functionality

// Terminal output handling with improved formatting
function appendToTerminal(terminalId, text, className = '') {
    const terminal = document.getElementById(terminalId);
    if (!terminal) return;
    
    // Check if we're in the API bypass terminal (which needs special formatting)
    const isApiBypassTerminal = terminalId === 'bypass-terminal';
    
    if (isApiBypassTerminal) {
        // Process the text line by line to apply appropriate styling for API bypass output
        const lines = text.split('\n');
        lines.forEach(line => {
            const lineElement = document.createElement('div');
            
            // Apply special formatting
            if (line.includes('<200>')) {
                // Success line (200 status)
                lineElement.className = 'success-line';
                line = line.replace('<200>', '');
            } else if (line.includes('<===HEADER=')) {
                // Header line
                lineElement.className = 'header-line';
                line = line.replace(/<===HEADER=/g, '').replace(/HEADER=>/g, '');
            } else if (line.includes('Error')) {
                // Error line
                lineElement.className = 'error-line';
            } else {
                // Regular line
                lineElement.className = 'command-line';
                if (className) {
                    lineElement.className += ' ' + className;
                }
            }
            
            lineElement.textContent = line;
            terminal.appendChild(lineElement);
        });
    } else {
        // Standard terminal output for scanner and other terminals
        const line = document.createElement('div');
        if (className) {
            line.className = className;
        }
        
        // Handle HTML content if present
        if (text.includes('<') && text.includes('>') && text.includes('</')) {
            line.innerHTML = text;
        } else {
            line.textContent = text;
        }
        
        terminal.appendChild(line);
    }
    
    terminal.scrollTop = terminal.scrollHeight;
}

// Clear terminal
function clearTerminal(terminalId) {
    const terminal = document.getElementById(terminalId);
    if (terminal) {
        terminal.innerHTML = '';
    }
}

// Format date for display
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Filter domains by technology
function filterByTechnology(technology) {
    let url = new URL(window.location);
    if (technology) {
        url.searchParams.set('technology', technology);
    } else {
        url.searchParams.delete('technology');
    }
    window.location.href = url.toString();
}

// Filter domains by status
function filterByStatus(status) {
    let url = new URL(window.location);
    if (status) {
        url.searchParams.set('status', status);
    } else {
        url.searchParams.delete('status');
    }
    window.location.href = url.toString();
}

// Filter domains by assessment status
function filterByAssessment(assessment) {
    let url = new URL(window.location);
    if (assessment) {
        url.searchParams.set('assessment', assessment);
    } else {
        url.searchParams.delete('assessment');
    }
    window.location.href = url.toString();
}

// Reset filters
function resetFilters() {
    window.location.href = "/domains";
}

// For the scanning functionality
function scanDomain() {
    const domain = document.getElementById('single-domain-input').value.trim();
    if (!domain) {
        alert('Please enter a domain to scan');
        return;
    }
    
    clearTerminal('scan-terminal');
    appendToTerminal('scan-terminal', `Starting scan for ${domain}...`);
    
    // Here you'd make an AJAX request to the backend
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `single_domain=${encodeURIComponent(domain)}`
    })
    .then(response => response.json())
    .then(data => {
        appendToTerminal('scan-terminal', `\nScan completed for ${data.domain}`);
        appendToTerminal('scan-terminal', `Status: ${data.status}`);
        appendToTerminal('scan-terminal', `Technologies detected: ${data.technologies.join(', ') || 'None'}`);
        
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            appendToTerminal('scan-terminal', `\nVulnerabilities found: ${data.vulnerabilities.length}`, 'text-danger');
            data.vulnerabilities.forEach(vuln => {
                appendToTerminal('scan-terminal', ` - ${vuln}`, 'text-warning');
            });
            
            // If domain has 403 errors, suggest API bypass
            if (data.has_403_error) {
                appendToTerminal('scan-terminal', `\n403 Forbidden error detected. Consider using the API Endpoint Bypass tool:`, 'text-info');
                appendToTerminal('scan-terminal', `<a href="/api-bypass?domain=${encodeURIComponent(data.domain)}" class="btn btn-sm btn-info mt-2">Try API Endpoint Bypass</a>`, '');
            }
        } else {
            appendToTerminal('scan-terminal', '\nNo vulnerabilities detected');
        }
    })
    .catch(error => {
        appendToTerminal('scan-terminal', `Error during scan: ${error}`, 'text-danger');
    });
}

function scanDomainList() {
    const domainList = document.getElementById('domain-list-input').value.trim();
    if (!domainList) {
        alert('Please enter domains to scan');
        return;
    }
    
    const domains = domainList.split('\n').filter(d => d.trim());
    
    clearTerminal('scan-terminal');
    appendToTerminal('scan-terminal', `Starting scan for ${domains.length} domains...`);
    
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `domain_list=${encodeURIComponent(domainList)}`
    })
    .then(response => response.json())
    .then(results => {
        appendToTerminal('scan-terminal', `\nReceived results for ${results.length} domains`);
        
        results.forEach((data, index) => {
            appendToTerminal('scan-terminal', `\n--- ${data.domain} (${index + 1}/${results.length}) ---`);
            appendToTerminal('scan-terminal', `Status: ${data.status}`);
            appendToTerminal('scan-terminal', `Technologies: ${data.technologies.join(', ') || 'None'}`);
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                appendToTerminal('scan-terminal', `Vulnerabilities found: ${data.vulnerabilities.length}`, 'text-danger');
                data.vulnerabilities.forEach(vuln => {
                    appendToTerminal('scan-terminal', ` - ${vuln}`, 'text-warning');
                });
                
                // If domain has 403 errors, suggest API bypass
                if (data.has_403_error) {
                    appendToTerminal('scan-terminal', `403 Forbidden error detected. Consider using the API Endpoint Bypass tool.`, 'text-info');
                }
            } else {
                appendToTerminal('scan-terminal', 'No vulnerabilities detected');
            }
        });
    })
    .catch(error => {
        appendToTerminal('scan-terminal', `Error during scan: ${error}`, 'text-danger');
    });
}

// For the API bypass functionality
function runApiBypass() {
    const domain = document.getElementById('bypass-domain-input').value.trim();
    const wordlist = document.getElementById('wordlist-select').value;
    
    if (!domain || !wordlist) {
        alert('Please enter a domain and select a wordlist');
        return;
    }
    
    clearTerminal('bypass-terminal');
    appendToTerminal('bypass-terminal', `Starting 403 bypass test for ${domain} using ${wordlist}...`);
    
    // Show clear results button if it exists
    const clearButton = document.getElementById('clear-results-btn');
    if (clearButton) {
        clearButton.style.display = 'block';
    }
    
    // Hide recommendations while test is running
    const recommendationsSection = document.getElementById('recommendations-section');
    if (recommendationsSection) {
        recommendationsSection.style.display = 'none';
    }
    
    fetch('/run-bypass', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `domain=${encodeURIComponent(domain)}&wordlist=${encodeURIComponent(wordlist)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            appendToTerminal('bypass-terminal', `Error: ${data.error}`, 'error-line');
            return;
        }
        
        // Clear the terminal before showing results
        clearTerminal('bypass-terminal');
        
        // Display full output in terminal with appropriate styling
        appendToTerminal('bypass-terminal', data.output);
        
        // Display recommendations and successful bypasses if any
        if (recommendationsSection) {
            if (data.successful_bypasses && data.successful_bypasses.length > 0) {
                recommendationsSection.style.display = 'block';
                
                const recommendationsContent = document.getElementById('recommendations-content');
                if (recommendationsContent) {
                    recommendationsContent.innerText = data.recommendations;
                }
                
                const bypassList = document.getElementById('successful-bypasses-list');
                if (bypassList) {
                    bypassList.innerHTML = '';
                    
                    data.successful_bypasses.forEach(bypass => {
                        const item = document.createElement('div');
                        item.className = 'list-group-item list-group-item-success';
                        item.innerHTML = `<code>${bypass}</code>`;
                        bypassList.appendChild(item);
                    });
                }
            } else {
                recommendationsSection.style.display = 'block';
                
                const recommendationsContent = document.getElementById('recommendations-content');
                if (recommendationsContent) {
                    recommendationsContent.innerText = "No successful bypasses found. The endpoint may not be vulnerable to 403 bypass techniques.";
                }
                
                const bypassList = document.getElementById('successful-bypasses-list');
                if (bypassList) {
                    bypassList.innerHTML = '<div class="list-group-item">No successful bypasses found</div>';
                }
            }
        }
    })
    .catch(error => {
        appendToTerminal('bypass-terminal', `Error during bypass test: ${error}`, 'error-line');
    });
}

// Initialize tooltips and popovers on document ready
document.addEventListener('DOMContentLoaded', function() {
    // Update filter dropdowns based on URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const techFilter = urlParams.get('technology');
    const statusFilter = urlParams.get('status');
    const assessmentFilter = urlParams.get('assessment');
    
    const techFilterElement = document.getElementById('technologyFilter');
    const statusFilterElement = document.getElementById('statusFilter');
    const assessmentFilterElement = document.getElementById('assessmentFilter');
    
    if (techFilterElement && techFilter) {
        techFilterElement.value = techFilter;
    }
    
    if (statusFilterElement && statusFilter) {
        statusFilterElement.value = statusFilter;
    }
    
    if (assessmentFilterElement && assessmentFilter) {
        assessmentFilterElement.value = assessmentFilter;
    }
    
    // Initialize any custom file inputs
    const customFileInputs = document.querySelectorAll('.custom-file-input');
    if (customFileInputs.length > 0) {
        customFileInputs.forEach(input => {
            input.addEventListener('change', function() {
                let fileName = this.value.split('\\').pop();
                const label = this.nextElementSibling;
                if (label && label.classList.contains('custom-file-label')) {
                    label.textContent = fileName || 'Choose file';
                }
            });
        });
    }
});
