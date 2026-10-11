
document.addEventListener("DOMContentLoaded", () => {
    // Toggle password visibility on inputs marked with data-toggle-password.
    document.querySelectorAll("[data-toggle-password]").forEach((button) => {
        button.addEventListener("click", () => {
            const targetId = button.dataset.togglePassword;
            const input = document.getElementById(targetId);

            if (!input) return;

            const showing = input.type === "text";
            input.type = showing ? "password" : "text";
            button.textContent = showing ? "Show" : "Hide";
            button.setAttribute(
                "aria-label",
                showing ? "Show password" : "Hide password"
            );
        });
    });

    // Basic client-side signup validation.
    const signupForm = document.querySelector("[data-signup-form]");

    if (signupForm) {
        signupForm.addEventListener("submit", (event) => {
            const password = signupForm.querySelector(
                'input[name="password"]'
            );
            const confirm = signupForm.querySelector(
                'input[name="confirm_password"]'
            );

            if (password && password.value.length < 12) {
                event.preventDefault();
                alert("Your password must be at least 12 characters long.");
                password.focus();
                return;
            }

            if (password && confirm && password.value !== confirm.value) {
                event.preventDefault();
                alert("The passwords do not match.");
                confirm.focus();
            }
        });
    }
});
