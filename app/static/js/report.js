// The report's print button. A script of its own because the pages allow no inline scripts.
document.querySelectorAll("[data-print]").forEach(function (button) {
  button.addEventListener("click", function () {
    window.print();
  });
});
