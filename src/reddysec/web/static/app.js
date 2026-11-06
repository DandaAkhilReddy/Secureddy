/* Secureddy — small progressive enhancements. Everything works without
   this file; it adds confirmations, flash dismissal, form hints, the
   installable-app bits (service worker, install button, iOS hint) and
   keyboard closing for the actions sheet. No inline scripts (CSP). */
(function () {
  "use strict";

  var store = {
    get: function (key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } },
    set: function (key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* private mode */ } }
  };

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

  // IMAP form: pick the provider from the address, show server fields only
  // for "Other", and open the matching steps.
  var provider = document.getElementById("imap-provider");
  if (provider) {
    var custom = document.getElementById("imap-custom");
    var address = document.getElementById("imap-address");
    var hint = document.getElementById("imap-detected");
    var domainsNode = document.getElementById("provider-domains");
    var domains = {};
    try { domains = JSON.parse(domainsNode ? domainsNode.textContent : "{}") || {}; } catch (e) { domains = {}; }
    var sync = function () {
      var key = provider.value;
      if (custom) {
        custom.hidden = key !== "imap";
      }
      document.querySelectorAll(".provider-steps").forEach(function (details) {
        details.open = details.getAttribute("data-provider") === key;
      });
    };
    var detect = function () {
      if (!address) { return; }
      var value = (address.value || "").trim().toLowerCase();
      var at = value.lastIndexOf("@");
      var found = at > 0 ? domains[value.slice(at + 1)] : null;
      if (found && provider.querySelector('option[value="' + found + '"]')) {
        provider.value = found;
        if (hint) { hint.hidden = false; }
        sync();
      }
    };
    provider.addEventListener("change", function () { if (hint) { hint.hidden = true; } sync(); });
    if (address) { address.addEventListener("change", detect); address.addEventListener("blur", detect); }
    sync();
  }

  // Actions sheet on the report (phones): Escape closes it. "#_" names no
  // element, so closing never scrolls the page.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && window.location.hash === "#decide") {
      window.location.hash = "_";
      var trigger = document.querySelector(".sheet-open");
      if (trigger) { trigger.focus(); }
    }
  });

  // ---------------------------------------------------------------- PWA
  if ("serviceWorker" in navigator && window.isSecureContext) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function () { /* the site works without it */ });
    });
  }

  var standalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;

  // Chromium: offer "Install Secureddy" in the user menu once the browser says it can.
  var installButton = document.querySelector("[data-install]");
  var deferredPrompt = null;
  window.addEventListener("beforeinstallprompt", function (event) {
    event.preventDefault();
    deferredPrompt = event;
    if (installButton && !standalone) { installButton.hidden = false; }
  });
  if (installButton) {
    installButton.addEventListener("click", function () {
      if (!deferredPrompt) { return; }
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function () {
        deferredPrompt = null;
        installButton.hidden = true;
      });
    });
  }
  window.addEventListener("appinstalled", function () {
    if (installButton) { installButton.hidden = true; }
  });

  // iOS Safari has no install prompt: show a one-time hint.
  var iosHint = document.querySelector("[data-ios-hint]");
  if (iosHint) {
    var ua = window.navigator.userAgent || "";
    var isIos = /iPad|iPhone|iPod/.test(ua) || (ua.indexOf("Macintosh") !== -1 && "ontouchend" in document);
    var isSafari = /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS/.test(ua);
    if (isIos && isSafari && !standalone && store.get("rs-ios-hint") !== "done") {
      iosHint.hidden = false;
      var dismiss = iosHint.querySelector("[data-ios-hint-close]");
      if (dismiss) {
        dismiss.addEventListener("click", function () {
          iosHint.hidden = true;
          store.set("rs-ios-hint", "done");
        });
      }
    }
  }
})();
