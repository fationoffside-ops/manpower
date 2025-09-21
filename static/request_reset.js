document.addEventListener('DOMContentLoaded', function() {
    var form = document.getElementById('requestResetForm');
    var msg = document.getElementById('resetSuccessMsg');
    if(form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            var email = form.email.value.trim();
            if(!email) return;
            form.querySelector('button[type="submit"]').disabled = true;
            fetch('/api/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            })
            .then(r => r.json())
            .then(j => {
                if(j.success) {
                    form.style.display = 'none';
                    msg.textContent = 'If your email is registered, a reset link has been sent.';
                    msg.style.display = 'block';
                } else {
                    msg.textContent = j.message || 'Failed to send reset link.';
                    msg.style.display = 'block';
                    form.querySelector('button[type="submit"]').disabled = false;
                }
            })
            .catch(() => {
                msg.textContent = 'An error occurred. Please try again.';
                msg.style.display = 'block';
                form.querySelector('button[type="submit"]').disabled = false;
            });
        });
    }
});