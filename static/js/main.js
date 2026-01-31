document.addEventListener('DOMContentLoaded', () => {
    const themeBtn = document.getElementById('themeToggle');
    const icon = themeBtn.querySelector('i');
    const html = document.documentElement;

    // 1. Check Local Storage on Load
    const savedTheme = localStorage.getItem('theme') || 'dark';
    html.setAttribute('data-theme', savedTheme);
    updateIcon(savedTheme);

    // 2. Button Click Event
    themeBtn.addEventListener('click', () => {
        const currentTheme = html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        // Apply new theme
        html.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateIcon(newTheme);
    });

    // Helper: Update the Sun/Moon Icon
    function updateIcon(theme) {
        if (theme === 'light') {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        } else {
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
        }
    }
});

// Password Toggle Logic (Keep this existing code)
function togglePassword(fieldId) {
    var passwordInput = document.getElementById(fieldId);
    var icon = document.querySelector(`[onclick="togglePassword('${fieldId}')"] i`);
    
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    } else {
        passwordInput.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
}