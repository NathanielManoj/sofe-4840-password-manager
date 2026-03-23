// Ashka Patel (100871256)
// SOFE 4840U - Computer Security

// ─── Base64 Helpers ───────────────────────────────────────────
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ─── PBKDF2 Key Derivation ────────────────────────────────────
async function deriveKey(password, salt) {
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 600000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// ─── Login Handler ────────────────────────────────────────────
async function handleLogin() {
    const password = document.getElementById('password').value;
    
    if (!password) {
        showError('Please enter your master password');
        return;
    }

    try {
        const saltResponse = await fetch('/get-salt');
        const saltData = await saltResponse.json();

        let saltBuffer;
        if (saltData.exists) {
            saltBuffer = base64ToArrayBuffer(saltData.salt);
        } else {
            saltBuffer = window.crypto.getRandomValues(new Uint8Array(16)).buffer;
        }

        const key = await deriveKey(password, saltBuffer);
        const rawKey = await window.crypto.subtle.exportKey("raw", key);

        const keyBase64 = arrayBufferToBase64(rawKey);
        const saltBase64 = arrayBufferToBase64(saltBuffer);

        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                key: keyBase64, 
                salt: saltBase64 
            })
        });

        const data = await response.json();

        if (data.success) {
            window.location.href = '/dashboard';
        } else {
            showError('Invalid master password');
        }

    } catch (error) {
        showError('An error occurred. Please try again.');
        console.error(error);
    }
}

function showError(message) {
    const errorDiv = document.getElementById('error');
    if (errorDiv) errorDiv.textContent = message;
}

// ─── Password Strength Checker ────────────────────────────────
function checkStrength(password) {
    let strength = 0;
    if (password.length >= 12) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
}

function updateStrengthIndicator(password) {
    const strength = checkStrength(password);
    const indicator = document.getElementById('strength-indicator');
    if (!indicator) return;
    
    if (strength <= 1) {
        indicator.textContent = 'Weak';
        indicator.className = 'strength weak';
    } else if (strength <= 3) {
        indicator.textContent = 'Medium';
        indicator.className = 'strength medium';
    } else {
        indicator.textContent = 'Strong';
        indicator.className = 'strength strong';
    }
}

// ─── Password Reveal Toggle ───────────────────────────────────
function togglePassword(index) {
    const field = document.getElementById(`password-${index}`);
    const button = document.getElementById(`toggle-${index}`);
    if (!field || !button) return;
    
    if (field.type === 'password') {
        field.type = 'text';
        button.textContent = 'Hide';
    } else {
        field.type = 'password';
        button.textContent = 'Show';
    }
}

// ─── Add Credential ───────────────────────────────────────────
async function handleAdd() {
    const service = document.getElementById('service').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('new-password').value;

    if (!service || !username || !password) {
        showError('Please fill in all fields');
        return;
    }

    const response = await fetch('/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service, username, password })
    });

    const data = await response.json();
    if (data.success) {
        window.location.reload();
    }
}

// ─── Delete Credential ────────────────────────────────────────
async function handleDelete(index) {
    if (!confirm('Are you sure you want to delete this credential?')) return;

    const response = await fetch('/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index })
    });

    const data = await response.json();
    if (data.success) {
        window.location.reload();
    }
}