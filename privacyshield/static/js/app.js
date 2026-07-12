/**
 * PrivacyShield — small client-side interaction helpers.
 * No frameworks; kept dependency-free per the project's Flask/Bootstrap-light stack.
 */

function initUploadForm() {
  const dropzone = document.getElementById("dropzone");
  const input = document.getElementById("dataset-input");
  const title = document.getElementById("dropzone-title");
  const submitBtn = document.getElementById("upload-submit");
  const form = document.getElementById("upload-form");

  if (!dropzone || !input) return;

  function setFile(file) {
    if (!file) return;
    title.textContent = file.name;
    dropzone.classList.add("has-file");
    submitBtn.disabled = false;
  }

  input.addEventListener("change", () => {
    if (input.files && input.files[0]) setFile(input.files[0]);
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("is-dragover");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("is-dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) {
      input.files = e.dataTransfer.files;
      setFile(file);
    }
  });

  form.addEventListener("submit", () => {
    submitBtn.disabled = true;
    submitBtn.textContent = "Uploading…";
  });
}

/**
 * Keep each column-card's checkbox and its type <select> in sync visually,
 * and let clicking anywhere on the card toggle the checkbox (except the select itself).
 */
function initSelectAllSync() {
  const cards = document.querySelectorAll(".column-card");
  cards.forEach((card) => {
    const select = card.querySelector(".type-select");
    if (select) {
      select.addEventListener("click", (e) => e.stopPropagation());
      select.addEventListener("mousedown", (e) => e.stopPropagation());
    }
  });

  const form = document.getElementById("anonymize-form");
  if (form) {
    form.addEventListener("submit", (e) => {
      const anyChecked = form.querySelectorAll('input[name="selected_columns"]:checked').length > 0;
      if (!anyChecked) {
        e.preventDefault();
        alert("Please select at least one column to anonymize.");
      }
    });
  }
}
