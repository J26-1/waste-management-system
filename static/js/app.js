document.addEventListener("input", function (event) {
    if (!event.target.matches("[data-table-search]")) {
        return;
    }

    const search = event.target.value.trim().toLowerCase();
    const panel = event.target.closest(".panel");
    const table = panel ? panel.querySelector("table[data-filterable]") : null;
    if (!table) {
        return;
    }

    table.querySelectorAll("tbody tr").forEach(function (row) {
        const text = row.textContent.toLowerCase();
        row.hidden = search && !text.includes(search);
    });
});

document.addEventListener("change", function (event) {
    if (event.target.name !== "outcome") {
        return;
    }

    const form = event.target.closest("form");
    const weight = form ? form.querySelector('[name="actual_organic_kg"]') : null;
    if (!weight) {
        return;
    }

    if (event.target.value === "failed") {
        weight.value = "0";
    }
});
