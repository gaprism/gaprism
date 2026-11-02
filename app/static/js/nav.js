// The sidebar's collapse button. A script of its own because the pages allow no inline scripts, loaded
// in the head and not deferred so that a collapsed sidebar is collapsed from the first paint. The
// choice stays in the browser's own storage; nothing is sent anywhere.
(function () {
  var root = document.documentElement;
  var KEY = "gaprism-nav";

  root.classList.add("js");
  try {
    if (window.localStorage.getItem(KEY) === "rail") {
      root.dataset.nav = "rail";
    }
  } catch (error) {
    // Storage is blocked: the sidebar starts expanded on every page.
  }

  function show(button) {
    var rail = root.dataset.nav === "rail";
    var label = rail ? button.dataset.labelExpand : button.dataset.labelCollapse;
    button.setAttribute("aria-expanded", rail ? "false" : "true");
    button.setAttribute("aria-label", label);
    button.dataset.tip = label;
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-nav-toggle]");
    if (!button) {
      return;
    }
    var rail = root.dataset.nav !== "rail";
    if (rail) {
      root.dataset.nav = "rail";
    } else {
      delete root.dataset.nav;
    }
    try {
      window.localStorage.setItem(KEY, rail ? "rail" : "full");
    } catch (error) {
      // Storage is blocked: the choice holds until the next page.
    }
    show(button);
  });

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-nav-toggle]").forEach(show);
  });
})();
