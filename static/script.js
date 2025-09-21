// Utility function for smooth number animation
function animateNumber(elementId, start, end, duration) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const startTime = performance.now();
    const easeOutCubic = t => 1 - Math.pow(1 - t, 3);
    
    const animate = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Use easing function for smoother animation
        const easedProgress = easeOutCubic(progress);
        
        // Handle decimal values for ratings
        const current = Number.isInteger(end) ? 
            Math.floor(start + (end - start) * easedProgress) :
            (start + (end - start) * easedProgress).toFixed(1);
            
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    };
    requestAnimationFrame(animate);
}

// Load and animate platform statistics
async function loadStats() {
    try {
        const response = await fetch('/api/contracts');
        const contracts = await response.json();
        
        const totalContracts = contracts.length;
        const verifiedAgencies = Math.floor(totalContracts * 0.8);
        const successfulMatches = Math.floor(totalContracts * 0.7);
        const avgRating = 4.8; // Default value
        
        // Animate all stats
        document.querySelectorAll('.stat-number').forEach(el => {
            let value = 0;
            switch(el.id) {
                case 'total-contracts': value = totalContracts; break;
                case 'verified-agencies': value = verifiedAgencies; break;
                case 'successful-matches': value = successfulMatches; break;
                case 'avg-rating': value = avgRating; break;
            }
            if (value !== undefined) {
                animateNumber(el.id, 0, value, 1500);
            }
        });
    } catch (error) {
        console.error('Error loading stats:', error);
        // Fallback to sample data
        animateNumber('total-contracts', 0, 25, 1500);
        animateNumber('verified-agencies', 0, 18, 1500);
        animateNumber('successful-matches', 0, 22, 1500);
        animateNumber('avg-rating', 0, 4.8, 1500);
    }
}

function initializeEventListeners() {
    // Handle navigation buttons with data-href
    document.querySelectorAll('[data-href]').forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const href = e.currentTarget.dataset.href;
            const userType = e.currentTarget.closest('.cta-card')?.classList.contains('contractors') ? 'contractors' :
                           e.currentTarget.closest('.cta-card')?.classList.contains('agency') ? 'agency' :
                           e.currentTarget.closest('.cta-card')?.classList.contains('individual') ? 'individual' : null;

            // If user type is available and trying to access dashboard
            if (userType && href === '/dashboard') {
                // Check if logged in
                if (!document.cookie.includes('manpower_user=')) {
                    openAuth('signup', userType);
                    return;
                }
            }

            // If marketplace or logged in, proceed with navigation
            window.location.href = href;
        });
    });

    // Handle auth action buttons (Sign In/Sign Up)
    document.querySelectorAll('[data-auth-action]').forEach(button => {
        button.addEventListener('click', (e) => {
            const action = e.currentTarget.dataset.authAction;
            const userType = e.currentTarget.dataset.userType;
            openAuth(action, userType);
            e.preventDefault();
        });
    });

    // Handle auth form switching
    document.querySelectorAll('[data-switch]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const action = e.currentTarget.dataset.switch;
            showAuthTab(action);
        });
    });

    // Set up auth modal handlers
    const modal = document.getElementById('authModal');
    if (modal) {
        // Add click handlers for modal close
        document.querySelectorAll('[data-modal-close]').forEach(button => {
            button.addEventListener('click', closeAuth);
        });

        // Close modal on outside click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeAuth();
            }
        });

        // Handle ESC key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.getAttribute('aria-hidden') === 'false') {
                closeAuth();
            }
        });
    }

    // Add form submit handlers
    document.querySelectorAll('form').forEach(form => {
        if (!form || !form.id) return;  // Skip if form is invalid

        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const submitButton = form.querySelector('button[type="submit"]');
            const originalText = submitButton?.innerHTML || 'Submit';
            
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML = 'Please wait...';
            }
            
            try {
                if (form.id === 'signinForm') {
                    handleSignIn(form);
                } else if (['individualForm', 'contractorsForm', 'agencyForm'].includes(form.id)) {
                    handleSignUp(form);
                } else if (form.id === 'resetPasswordForm') {
                    handlePasswordReset(form);
                } else if (form.id === 'applicationForm') {
                    handleApplicationSubmit(form);
                }
            } catch (error) {
                console.error('Form submission error:', error);
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = submitButton.dataset.originalText || originalText;
                }
                alert('An error occurred. Please try again.');
            }
        });

        // Store original button text
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.dataset.originalText = submitButton.innerHTML;
        }
    });
    
    // Handle user type selection cards
    document.querySelectorAll('.user-type-card[data-select-type]').forEach(card => {
        // Make cards keyboard focusable
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.setAttribute('aria-pressed', 'false');
        
        // Handle both click and keyboard interactions
        const handleSelection = (e) => {
            e.preventDefault();
            
            // Remove active state from all cards
            document.querySelectorAll('.user-type-card').forEach(c => {
                c.classList.remove('active', 'selected');
                c.setAttribute('aria-pressed', 'false');
            });
            
            // Add visual feedback
            card.classList.add('active', 'selected');
            card.setAttribute('aria-pressed', 'true');
            
            // Handle the selection
            const userType = card.dataset.selectType;
            if (userType) {
                handleUserTypeSelection(userType);
            }
            
            // Remove selection animation after delay
            setTimeout(() => {
                card.classList.remove('selected');
            }, 500);
        };
        
        // Add event listeners
        card.addEventListener('click', handleSelection);
        card.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                handleSelection(e);
            }
        });
    });
}

// Handle the user type selection process
function handleUserTypeSelection(type) {
    if (!type) {
        console.error('No user type provided');
        return;
    }

    try {
        // Show loading state
        const selectedCard = document.querySelector(`.user-type-card[data-select-type="${type}"]`);
        if (selectedCard) {
            selectedCard.classList.add('active', 'loading');
        }

        // Find the form for this user type
        const formId = `${type}Form`;
        const userTypeForm = document.getElementById(formId);
        const userTypeSelection = document.getElementById('userTypeSelection');

        // Hide type selection if it exists
        if (userTypeSelection) {
            userTypeSelection.style.display = 'none';
        }

        if (!userTypeForm) {
            window.location.href = `/signup?type=${type}`;
            return;
        }

        // Reset all forms
        document.querySelectorAll('.auth-form').forEach(form => {
            form.style.display = 'none';
            form.classList.remove('form-appear');
        });

        // Show and animate the selected form
        userTypeForm.style.display = 'flex';
        // Only trigger reflow and add animation if form is in the DOM
        if (document.body.contains(userTypeForm)) {
            void userTypeForm.offsetWidth; // Trigger reflow
            userTypeForm.classList.add('form-appear');
            
            // Focus first input field
            const firstInput = userTypeForm.querySelector('input:not([type="hidden"])');
            if (firstInput) {
                setTimeout(() => {
                    firstInput.focus();
                }, 300);
            }

            // Remove loading state
            if (selectedCard) {
                setTimeout(() => {
                    selectedCard.classList.remove('loading');
                }, 500);
            }
        } else {
            // If no form exists, redirect to signup page
            window.location.href = `/signup?type=${type}`;
        }
    } catch (error) {
        console.error('Error in handleUserTypeSelection:', error);
        alert('An error occurred. Please try again.');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add reveal animations with staggered timing
    const elements = document.querySelectorAll('.hero-copy, .hero-card, .step, .feature-card, .stat-card, .cta-card');
    elements.forEach((el, index) => {
        setTimeout(() => {
            el.classList.add('reveal');
        }, 120 + (index * 50)); // Stagger each element by 50ms
    });

    // Load stats if stats section exists
    if (document.querySelector('.stats-section')) {
        loadStats();
    }

    // Initialize all event listeners
    initializeEventListeners();

    // Auto-load marketplace/inbox for relevant pages
    if (document.getElementById('marketplaceList')) {
        loadMarketplaceActions('marketplaceList');
    }
    if (document.getElementById('inboxList')) {
        loadInbox();
    }
});

// Auth modal functions
function openAuth(tab, userType) {
    const modal = document.getElementById('authModal');
    if (!modal) return;
    
    // Save the current focus
    modal._lastFocus = document.activeElement;
    
    // Show modal and prevent background scrolling
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    
    // Reset any previous form state
    document.querySelectorAll('#authModal form').forEach(form => {
        form.reset();
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = submitBtn.dataset.originalText || 'Submit';
        }
    });
    
    // Show appropriate content
    if (tab === 'signup' && userType) {
        showAuthTab('signup');
        setTimeout(() => {
            const userTypeForm = document.getElementById(`${userType}Form`);
            if (userTypeForm) {
                hideAllForms();
                userTypeForm.style.display = 'flex';
                const firstInput = userTypeForm.querySelector('input:not([type="hidden"])');
                if (firstInput) {
                    firstInput.focus();
                }
            } else {
                selectUserType(userType);
            }
        }, 100);
    } else {
        showAuthTab(tab || 'signin');
    }
    
    // Focus first focusable element
    const firstFocusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (firstFocusable) {
        firstFocusable.focus();
    }
}

function closeAuth() {
    const modal = document.getElementById('authModal');
    if (!modal) return;
    
    // Hide modal and restore background scrolling
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    
    // Reset to default state
    hideAllForms();
    
    // Restore focus
    if (modal._lastFocus && typeof modal._lastFocus.focus === 'function') {
        modal._lastFocus.focus();
    }
}

function showAuthTab(tab) {
    document.querySelectorAll('.auth-tabs .tab').forEach(t => t.classList.remove('active'));
    const tabElement = document.getElementById(`tab-${tab}`);
    if (tabElement) {
        tabElement.classList.add('active');
    }
    
    hideAllForms();
    
    if (tab === 'signin') {
        const splitLayout = document.querySelector('.auth-split-layout');
        const signinForm = document.getElementById('signinForm');
        
        if (splitLayout) splitLayout.style.display = 'flex';
        if (signinForm) {
            signinForm.style.display = 'flex';
            // Focus the email input field
            const emailInput = signinForm.querySelector('input[type="email"]');
            if (emailInput) {
                emailInput.focus();
            }
        }
    } else if (tab === 'signup') {
        const userTypeSelection = document.getElementById('userTypeSelection');
        if (userTypeSelection) {
            userTypeSelection.style.display = 'block';
        }
    }
}

function hideAllForms() {
    const formsToHide = [
        '.auth-split-layout',
        '#userTypeSelection',
        '#resetPasswordForm',
        '#individualForm',
        '#contractorsForm',
        '#agencyForm'
    ];
    
    formsToHide.forEach(selector => {
        const element = document.querySelector(selector);
        if (element) {
            element.style.display = 'none';
        }
    });
}

// Form handling functions
function handleSignIn(form) {
    const data = {};
    new FormData(form).forEach((v, k) => data[k] = v);
    
    fetch('/api/signin', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify(data),
        credentials: 'include'
    })
    .then(r => r.ok ? r.json() : Promise.reject('Sign-in failed'))
    .then(j => {
        if (j && j.success) {
            window.location = j.redirect || '/dashboard';
        } else {
            throw new Error(j.message || 'Invalid credentials');
        }
    })
    .catch(error => {
        alert(error.message || 'Sign-in failed. Please check your credentials.');
        enableForm(form);
    });
}

function handleSignUp(form) {
    const data = {};
    new FormData(form).forEach((v, k) => data[k] = v);
    
    if (!validateSignUpForm(data, form.id)) {
        enableForm(form);
        return;
    }
    
    // Set user type based on form
    // Map form data to API expected fields
    if (form.id === 'contractorsForm') {
        data.company = data.companyName;
        data.contact = data.contactPerson;
        delete data.companyName;
        delete data.contactPerson;
    }
    
    data.signupRole = form.id.replace('Form', '');
    
    fetch('/api/signup', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify(data) 
    })
    .then(r => r.json())
    .then(j => {
        if (j.success) {
            alert(j.message || 'Registration successful! Please check your email to verify your account.');
            closeAuth();
            setTimeout(() => openAuth('signin'), 500);
        } else {
            handleSignupError(j, form);
        }
    })
    .catch(error => {
        console.error('Signup error:', error);
        alert('Registration failed. Please try again.');
        enableForm(form);
    });
}

function handlePasswordReset(form) {
    const data = {};
    new FormData(form).forEach((v, k) => data[k] = v);
    
    const endpoint = data.token ? '/api/set-password' : '/api/reset-password';
    const successMessage = data.token ? 
        'Password updated successfully!' : 
        'Password reset instructions have been sent to your email';
    
    if (data.token && data.password !== data.confirmPassword) {
        alert('Passwords do not match');
        return;
    }
    
    fetch(endpoint + (data.token ? '?token=' + encodeURIComponent(data.token) : ''), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(j => {
        if (j.success) {
            alert(successMessage);
            if (data.token) {
                window.location.href = '/';
            } else {
                showSignInForm();
            }
        } else {
            throw new Error(j.message || 'Failed to process request');
        }
    })
    .catch(error => {
        alert(error.message || 'An error occurred. Please try again.');
        enableForm(form);
    });
}

// Helper functions
function validateSignUpForm(data, formId) {
    const errors = [];
    
    // Common validations
    if (!data.password || data.password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    if (data.password !== data.confirmPassword) {
        errors.push('Passwords do not match');
    }
    if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
        errors.push('Please enter a valid email address');
    }
    if (!data.phone || !/^\+?[\d\s-]{8,}$/.test(data.phone)) {
        errors.push('Please enter a valid phone number');
    }
    
    // Form-specific validations
    if (formId === 'individualForm') {
        if (!data.firstName) errors.push('First name is required');
        if (!data.lastName) errors.push('Last name is required');
        if (!data.city) errors.push('Current city is required');
        if (!data.experience) errors.push('Experience level is required');
    } else if (formId === 'contractorsForm') {
        if (!data.companyName) errors.push('Company name is required');
        if (!data.contactPerson) errors.push('Contact person is required');
        if (!data.industry) errors.push('Industry is required');
        if (!data.city) errors.push('Company location is required');
    } else if (formId === 'agencyForm') {
        if (!data.agencyName) errors.push('Agency name is required');
        if (!data.contactPerson) errors.push('Contact person is required');
        if (!data.specializations) errors.push('Specializations are required');
        if (!data.city) errors.push('Primary location is required');
    }
    
    if (errors.length > 0) {
        alert('Please correct the following errors:\n\n' + errors.join('\n'));
        return false;
    }
    
    return true;
}

function enableForm(form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = submitBtn.dataset.originalText || 'Submit';
    }
}

function handleSignupError(response, form) {
    if (response.validation_errors) {
        const fields = response.validation_errors.fields || [];
        const general = response.validation_errors.general || [];
        
        fields.forEach(field => {
            const input = form.querySelector(`[name="${field}"]`);
            if (input) {
                input.classList.add('invalid');
                input.addEventListener('input', function() {
                    this.classList.remove('invalid');
                }, { once: true });
            }
        });
        
        alert([...fields, ...general].join('\n') || 'Please correct the errors in the form.');
    } else {
        alert(response.message || 'Registration failed. Please try again.');
    }
    enableForm(form);
}

// Social login functionality
function socialLogin(provider) {
    alert(`Social login with ${provider} will be implemented in the production version.`);
}