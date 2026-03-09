// ---------- Show/Hide Admin Password ----------
function togglePassword() {
  const pwd = document.getElementById("admin_password");
  if (!pwd) return;
  pwd.type = (pwd.type === "password") ? "text" : "password";
}

// ---------- Loading Spinner on Buttons ----------
function setLoading(btn, text) {
  if (!btn) return;
  btn.dataset.old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>${text}`;
}

document.addEventListener("DOMContentLoaded", () => {
  // Remember account number
  const accInput = document.getElementById("user_account");
  if (accInput) {
    const saved = localStorage.getItem("saved_account") || "";
    if (saved && !accInput.value) accInput.value = saved;

    accInput.addEventListener("input", () => {
      localStorage.setItem("saved_account", accInput.value.trim());
    });
  }

  // Loading on forms
  const userSendForm = document.getElementById("user_send_form");
  const userVerifyForm = document.getElementById("user_verify_form");
  const adminSendForm = document.getElementById("admin_send_form");
  const adminVerifyForm = document.getElementById("admin_verify_form");

  if (userSendForm) userSendForm.addEventListener("submit", () => setLoading(document.getElementById("btn_user_send"), "Sending OTP..."));
  if (userVerifyForm) userVerifyForm.addEventListener("submit", () => setLoading(document.getElementById("btn_user_verify"), "Verifying..."));
  if (adminSendForm) adminSendForm.addEventListener("submit", () => setLoading(document.getElementById("btn_admin_send"), "Sending OTP..."));
  if (adminVerifyForm) adminVerifyForm.addEventListener("submit", () => setLoading(document.getElementById("btn_admin_verify"), "Verifying..."));

  // Forgot account help
  const helpBtn = document.getElementById("forgot_help");
  if (helpBtn) {
    helpBtn.addEventListener("click", (e) => {
      e.preventDefault();
      alert("Demo Help: Contact Admin / Bank to get your Account Number.\n(Or check the uploaded users.csv in admin panel.)");
    });
  }
});