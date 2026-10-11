console.log("SecureDeps dashboard.js loaded!");
document.addEventListener("DOMContentLoaded", () => {
    // Confirm before logging out.
    document.querySelectorAll("[data-confirm-logout]").forEach((link) => {
        link.addEventListener("click", (event) => {
            if (!window.confirm("Are you sure you want to log out?")) {
                event.preventDefault();
            }
        });
    });

    // Dismissible messages.
    document.querySelectorAll("[data-dismissible]").forEach((message) => {
        const closeButton = message.querySelector("[data-dismiss]");

        if (closeButton) {
            closeButton.addEventListener("click", () => {
                message.remove();
            });
        }
    });
});
