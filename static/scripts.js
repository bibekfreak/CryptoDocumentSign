document.addEventListener("DOMContentLoaded", function () {
  const dropdownBtn = document.querySelector(".dropdown-btn");
  const userListDiv = document.getElementById("userList");
  const recipientsInput = document.getElementById("recipientsInput");

  const pdfInput = document.querySelector("input[name='document']");
  if (pdfInput) {
    pdfInput.addEventListener("change", function () {
      if (!this.value.endsWith(".pdf")) {
        alert("Only PDF files are allowed.");
        this.value = "";
      }
    });
  }

  if (!dropdownBtn || !userListDiv || !recipientsInput) return;

  dropdownBtn.addEventListener("click", () => {
    userListDiv.classList.toggle("show");
  });

  document.addEventListener("click", function (event) {
    if (
      !dropdownBtn.contains(event.target) &&
      !userListDiv.contains(event.target)
    ) {
      userListDiv.classList.remove("show");
    }
  });

  const loggedInEmail = document.querySelector(
    'meta[name="user-email"]'
  )?.content;

  fetch("/users")
    .then((response) => response.json())
    .then((users) => {
      if (!Array.isArray(users) || users.length === 0) {
        userListDiv.innerHTML = '<div class="empty-msg">No users found.</div>';
        return;
      }

      const searchInput = document.createElement("input");
      searchInput.type = "text";
      searchInput.placeholder = "Search...";
      searchInput.className = "dropdown-search";
      userListDiv.appendChild(searchInput);

      const container = document.createElement("div");
      container.className = "checkbox-list";

      users.forEach((user) => {
        if (user.email === loggedInEmail) return;

        const item = document.createElement("label");
        item.className = "checkbox-item";
        item.innerHTML = `
          <input type="checkbox" value="${user.email}">
          ${user.username} (${user.email})
        `;
        container.appendChild(item);
      });

      userListDiv.appendChild(container);

      container.addEventListener("change", () => {
        const selected = [...container.querySelectorAll("input:checked")].map(
          (cb) => cb.value
        );

        recipientsInput.innerHTML = "";

        // Add badges to display selected users
        if (selected.length > 0) {
          const badgeContainer = document.createElement("div");
          badgeContainer.className = "mb-2";
          selected.forEach((email) => {
            const badge = document.createElement("span");
            badge.className = "badge bg-success me-1";
            badge.textContent = email;
            badgeContainer.appendChild(badge);
          });
          recipientsInput.appendChild(badgeContainer);
        }

        // Add hidden inputs for submission
        selected.forEach((email) => {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = "recipients";
          input.value = email;
          recipientsInput.appendChild(input);
        });
      });

      searchInput.addEventListener("input", () => {
        const term = searchInput.value.toLowerCase();
        [...container.children].forEach((label) => {
          const text = label.textContent.toLowerCase();
          label.style.display = text.includes(term) ? "block" : "none";
        });
      });
    })
    .catch((err) => {
      console.error("Failed to fetch users:", err);
      userListDiv.innerHTML =
        '<div class="error-msg">Failed to load users.</div>';
    });
});
