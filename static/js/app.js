document.addEventListener("input", function (event) {
    if (!event.target.matches("[data-table-search]")) {
        return;
    }

    const search = event.target.value.trim().toLowerCase();
    const panel = event.target.closest(".panel");
    const table = panel ? panel.querySelector("table[data-filterable]") : null;
    const cards = panel ? panel.querySelectorAll(".source-registry-card") : [];
    if (!table && cards.length === 0) {
        return;
    }

    if (table) {
        table.querySelectorAll("tbody tr").forEach(function (row) {
            const text = row.textContent.toLowerCase();
            row.hidden = search && !text.includes(search);
        });
    }

    cards.forEach(function (card) {
        const text = card.textContent.toLowerCase();
        card.hidden = search && !text.includes(search);
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

document.addEventListener("click", function (event) {
    const popupClose = event.target.closest(".ops-popup-close");
    if (popupClose) {
        closeOpsMapPopup();
        return;
    }

    const selectButton = event.target.closest(".map-select");
    if (selectButton) {
        const frame = document.getElementById("googleMapFrame");
        if (frame && selectButton.dataset.mapUrl) {
            frame.src = selectButton.dataset.mapUrl;
        }

        document.querySelectorAll(".map-card, .sabah-location-card").forEach(function (card) {
            card.classList.remove("is-selected");
        });

        const card = selectButton.closest(".map-card, .sabah-location-card");
        if (card) {
            card.classList.add("is-selected");
        }

        document.querySelectorAll(".ops-map-marker").forEach(function (marker) {
            marker.classList.remove("is-active");
        });

        let marker = selectButton.closest(".ops-map-marker");
        if (!marker && selectButton.dataset.popupTarget) {
            document.querySelectorAll(".ops-map-marker").forEach(function (candidate) {
                if (candidate.dataset.popupTarget === selectButton.dataset.popupTarget) {
                    marker = candidate;
                }
            });
        }
        if (marker) {
            marker.classList.add("is-active");
        }

        if (selectButton.dataset.popupTarget) {
            openOpsMapPopup(selectButton.dataset.popupTarget, selectButton.dataset.popupKind || "");
        } else {
            closeOpsMapPopup();
        }
        return;
    }

    const filterButton = event.target.closest(".map-filter");
    if (!filterButton) {
        return;
    }

    document.querySelectorAll(".map-filter").forEach(function (button) {
        button.classList.remove("active");
    });
    filterButton.classList.add("active");
    applyMapFilters();
});

document.addEventListener("input", function (event) {
    if (!event.target.matches("[data-location-search]")) {
        return;
    }

    applyMapFilters();
});

function applyMapFilters() {
    const activeFilter = document.querySelector(".map-filter.active");
    const filter = activeFilter ? activeFilter.dataset.mapFilter : "all";
    const searchInput = document.querySelector("[data-location-search]");
    const search = searchInput ? searchInput.value.trim().toLowerCase() : "";

    document.querySelectorAll(".map-card").forEach(function (card) {
        const matchesType = filter === "all" || card.dataset.locationType === filter;
        const matchesSearch = !search || card.textContent.toLowerCase().includes(search);
        card.hidden = !(matchesType && matchesSearch);
    });
}

function openOpsMapPopup(templateId, kind) {
    const template = document.getElementById(templateId);
    const popup = document.getElementById("opsMapPopup");
    const body = popup ? popup.querySelector(".ops-map-popup-body") : null;
    if (!template || !popup || !body) {
        return;
    }

    body.innerHTML = template.innerHTML;
    popup.dataset.popupKind = kind;
    popup.hidden = false;
}

function closeOpsMapPopup() {
    const popup = document.getElementById("opsMapPopup");
    if (!popup) {
        return;
    }

    popup.hidden = true;
    const body = popup.querySelector(".ops-map-popup-body");
    if (body) {
        body.innerHTML = "";
    }
    document.querySelectorAll(".ops-map-marker").forEach(function (marker) {
        marker.classList.remove("is-active");
    });
}
