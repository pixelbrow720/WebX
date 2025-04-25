document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips if available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Flash message auto-dismiss
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        if (!alert.classList.contains('alert-persistent')) {
            setTimeout(() => {
                alert.style.opacity = '0';
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 500);
            }, 5000);
        }
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            } else {
                // Show loading spinner when form is submitted successfully
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    const originalText = submitBtn.innerHTML;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
                    submitBtn.disabled = true;
                    
                    // Store original button text for later restoration
                    submitBtn.dataset.originalText = originalText;
                }
                
                // Show loading overlay if it exists
                const loadingOverlay = document.getElementById('loading-overlay');
                if (loadingOverlay) {
                    loadingOverlay.style.display = 'flex';
                }
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Toggle password visibility
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', function() {
            const passwordInput = document.querySelector(this.getAttribute('data-target'));
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });
    });

    // JSON pretty printing
    const jsonContainers = document.querySelectorAll('.json-viewer');
    jsonContainers.forEach(container => {
        try {
            const jsonContent = container.textContent.trim();
            if (jsonContent) {
                const parsedJson = JSON.parse(jsonContent);
                const formattedJson = JSON.stringify(parsedJson, null, 2);
                container.textContent = formattedJson;
            }
        } catch (e) {
            console.error('Error formatting JSON:', e);
        }
    });

    // Collapsible sections
    const collapsibleHeaders = document.querySelectorAll('.collapsible-header');
    collapsibleHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const content = this.nextElementSibling;
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
                this.classList.remove('active');
            } else {
                content.style.maxHeight = content.scrollHeight + "px";
                this.classList.add('active');
            }
        });
    });

    // Toggle sections in vulnerability testing
    const toggleButtons = document.querySelectorAll('[data-toggle-target]');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-toggle-target');
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                if (targetElement.style.display === 'none' || !targetElement.style.display) {
                    targetElement.style.display = 'block';
                    this.textContent = this.getAttribute('data-hide-text') || 'Hide';
                } else {
                    targetElement.style.display = 'none';
                    this.textContent = this.getAttribute('data-show-text') || 'Show';
                }
            }
        });
    });

    // Add custom validation for URL fields
    const urlInputs = document.querySelectorAll('input[type="url"]');
    urlInputs.forEach(input => {
        input.addEventListener('blur', function() {
            let value = this.value.trim();
            if (value && !value.match(/^https?:\/\//)) {
                this.value = 'http://' + value;
            }
        });
    });

    // Dynamic form fields for exploit chain
    const addExploitBtn = document.getElementById('add-exploit-item');
    if (addExploitBtn) {
        addExploitBtn.addEventListener('click', function() {
            const container = document.getElementById('exploit-chain-container');
            const index = container.children.length;
            
            const selectOption = document.createElement('div');
            selectOption.className = 'form-group mb-2';
            selectOption.innerHTML = `
                <select name="exploit_chain" class="form-control" required>
                    <option value="">Select vulnerability type</option>
                    <option value="xss">Cross-Site Scripting (XSS)</option>
                    <option value="sql_injection">SQL Injection</option>
                    <option value="csrf">Cross-Site Request Forgery (CSRF)</option>
                    <option value="idor">Insecure Direct Object Reference (IDOR)</option>
                    <option value="ssti">Server-Side Template Injection (SSTI)</option>
                    <option value="auth_bypass">Authentication Bypass</option>
                    <option value="privilege_escalation">Privilege Escalation</option>
                </select>
            `;
            
            container.appendChild(selectOption);
        });
    }

    // Handle report generation request
    const generateReportBtn = document.getElementById('generate-report-btn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', function() {
            const loadingOverlay = document.getElementById('report-loading');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'flex';
            }
            
            // Submit the form after showing loading state
            const reportForm = document.getElementById('report-form');
            if (reportForm) {
                reportForm.submit();
            }
        });
    }
});
