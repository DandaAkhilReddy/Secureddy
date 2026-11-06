/* Secureddy — small progressive enhancements. Everything works without
   this file; it only adds confirmations, flash dismissal and form hints. */
(function () {
  "use strict";

  // Confirm destructive or consequential forms before they submit.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Flash messages: dismiss on click, and fade out success notices by themselves.
  document.querySelectorAll("[data-flash]").forEach(function (flash) {
    var close = flash.querySelector("[data-flash-close]");
    var remove = function () {
      if (flash.parentNode) {
        flash.parentNode.removeChild(flash);
      }
    };
    if (close) {
      close.addEventListener("click", remove);
    }
    if (flash.classList.contains("flash-ok")) {
      window.setTimeout(remove, 7000);
    }
  });

  // IMAP form: show server fields only for "Other", and open the matching steps.
  var provider = document.getElementById("imap-provider");
  if (provider) {
    var custom = document.getElementById("imap-custom");
    var sync = function () {
      var key = provider.value;
      if (custom) {
        custom.hidden = key !== "imap";
      }
      document.querySelectorAll(".provider-steps").forEach(function (details) {
        details.open = details.getAttribute("data-provider") === key;
      });
    };
    provider.addEventListener("change", sync);
    sync();
  }
})();
