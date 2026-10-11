
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector('form[action*="/api/scan"]');

    if (!form) return;

    const fileInput = form.querySelector('input[name="file"]');
    const submitButton = form.querySelector(
        'button[type="submit"], input[type="submit"]'
    );

    const status = document.createElement("div");
    status.id = "scan-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    form.insertAdjacentElement("afterend", status);

    const result = document.createElement("div");
    result.id = "scan-result";
    form.insertAdjacentElement("afterend", result);

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        result.replaceChildren();
        status.textContent = "";

        if (!fileInput || !fileInput.files.length) {
            status.textContent = "Please select a ZIP file first.";
            return;
        }

        const file = fileInput.files[0];

        if (!file.name.toLowerCase().endsWith(".zip")) {
            status.textContent = "Please select a .zip file.";
            return;
        }

        if (file.size > 200 * 1024 * 1024) {
            status.textContent = "The ZIP file must be 200 MB or smaller.";
            return;
        }

        const formData = new FormData(form);

        if (submitButton) submitButton.disabled = true;

        status.textContent = "Uploading and analyzing your project...";

        try {
            const response = await fetch(form.action, {
                method: "POST",
                body: formData,
                credentials: "same-origin"
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "The scan could not be completed.");
            }

            status.textContent = "Analysis completed successfully.";

            const heading = document.createElement("h3");
            heading.textContent = "Scan results";

            const summary = document.createElement("p");
            summary.textContent =
                `Files inspected: ${data.summary?.files_inspected ?? 0} | ` +
                `Findings: ${data.summary?.total_findings ?? 0}`;

            result.append(heading, summary);

            if (data.history_url) {
                const link = document.createElement("a");
                link.href = data.history_url;
                link.textContent = "View full security report";
                result.append(link);
            }

            // Refresh the dashboard history after a successful scan.
            if (data.scan_id) {
                const refresh = document.createElement("button");
                refresh.type = "button";
                refresh.textContent = "Refresh dashboard";
                refresh.addEventListener("click", () => location.reload());
                result.append(document.createElement("br"), refresh);
            }
        } catch (error) {
            status.textContent =
                error.message || "Something went wrong. Please try again.";
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });
});
