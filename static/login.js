(() => {
  "use strict";
  const pwd = document.getElementById("password");
  const btn = document.getElementById("reveal");
  const form = document.querySelector("form.auth-card");
  btn.addEventListener("click", () => {
    const show = pwd.type === "password";
    pwd.type = show ? "text" : "password";
    btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    btn.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
  });
  form.addEventListener("submit", () => {
    const b = document.getElementById("loginBtn");
    b.disabled = true; b.textContent = "Signing in…";
  });
})();
