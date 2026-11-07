/* Secureddy — app lock: PIN pad, passkey unlock, and adding a passkey in
   Settings. Progressive enhancement: the PIN and password forms work
   without this file. No innerHTML, no inline scripts (CSP). */
(function () {
  "use strict";

  // ---- base64url <-> ArrayBuffer (WebAuthn speaks bytes; the server JSON) --
  function fromB64url(value) {
    var b64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) { b64 += "="; }
    var raw = window.atob(b64);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) { out[i] = raw.charCodeAt(i); }
    return out.buffer;
  }

  function toB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var i = 0; i < bytes.length; i++) { raw += String.fromCharCode(bytes[i]); }
    return window.btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfOf(form) {
    var input = form && form.querySelector("input[name=csrf_token]");
    return input ? input.value : "";
  }

  function post(url, data) {
    return fetch(url, {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      return response.json().then(function (json) { return { ok: response.ok, json: json }; },
        function () { return { ok: response.ok, json: {} }; });
    });
  }

  function credentialJson(credential) {
    var r = credential.response;
    var out = {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      response: { clientDataJSON: toB64url(r.clientDataJSON) }
    };
    if (r.attestationObject) {
      out.response.attestationObject = toB64url(r.attestationObject);
      if (r.getTransports) { out.response.transports = r.getTransports(); }
    }
    if (r.authenticatorData) {
      out.response.authenticatorData = toB64url(r.authenticatorData);
      out.response.signature = toB64url(r.signature);
      out.response.userHandle = r.userHandle ? toB64url(r.userHandle) : null;
    }
    if (credential.authenticatorAttachment) { out.authenticatorAttachment = credential.authenticatorAttachment; }
    return JSON.stringify(out);
  }

  var webauthn = !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);

  // ---- PIN pad ---------------------------------------------------------------
  var form = document.querySelector("[data-lock-form]");
  var input = document.querySelector("[data-pin-input]");
  var pad = document.querySelector("[data-pin-pad]");
  var dots = document.querySelector("[data-pin-dots]");
  if (form && input && pad && dots) {
    var touch = window.matchMedia("(pointer: coarse)").matches;
    pad.hidden = false;
    form.classList.add("has-pad");
    if (touch) {
      input.setAttribute("readonly", "readonly"); // the pad replaces the phone keyboard
      input.removeAttribute("autofocus");
      input.blur();
    }
    var paint = function () {
      var n = input.value.length;
      dots.querySelectorAll("span").forEach(function (dot, i) { dot.classList.toggle("on", i < n); });
    };
    var maybeSubmit = function () {
      paint();
      if (/^\d{6}$/.test(input.value)) {
        form.classList.add("busy");
        form.submit();
      }
    };
    pad.addEventListener("click", function (event) {
      var key = event.target.closest ? event.target.closest("button") : null;
      if (!key || form.classList.contains("busy")) { return; }
      if (key.hasAttribute("data-digit") && input.value.length < 6) {
        input.value += key.getAttribute("data-digit");
        maybeSubmit();
      } else if (key.hasAttribute("data-back")) {
        input.value = input.value.slice(0, -1);
        paint();
      }
    });
    input.addEventListener("input", function () {
      input.value = input.value.replace(/\D/g, "").slice(0, 6);
      maybeSubmit();
    });
    var submitButton = form.querySelector("[data-pin-submit]");
    if (submitButton) { submitButton.hidden = true; }
    paint();
  }

  // ---- unlock with a passkey -------------------------------------------------
  var passkeyForm = document.querySelector("[data-passkey-form]");
  var message = document.querySelector("[data-passkey-msg]");
  function say(text) { if (message) { message.textContent = text; } }

  function unlockWithPasskey() {
    if (!passkeyForm) { return; }
    if (!webauthn) { say("This browser cannot use passkeys here. Please use your PIN."); return; }
    var data = new FormData();
    data.set("csrf_token", csrfOf(passkeyForm));
    say("Waiting for your passkey…");
    post("/lock/passkey/options", data).then(function (result) {
      if (!result.ok) { throw new Error("options"); }
      var o = result.json;
      return navigator.credentials.get({
        publicKey: {
          challenge: fromB64url(o.challenge),
          rpId: o.rpId,
          timeout: o.timeout,
          userVerification: o.userVerification || "required",
          allowCredentials: (o.allowCredentials || []).map(function (c) {
            return { type: "public-key", id: fromB64url(c.id), transports: c.transports };
          })
        }
      });
    }).then(function (credential) {
      var data2 = new FormData(passkeyForm);
      data2.set("credential", credentialJson(credential));
      return post("/lock/passkey", data2);
    }).then(function (result) {
      if (result.ok && result.json.next) {
        window.location.assign(result.json.next);
      } else {
        say(result.json.error || "That did not work. Please try again or use your PIN.");
      }
    }).catch(function () {
      say("Your passkey did not open Secureddy. Try again or use your PIN.");
    });
  }
  document.querySelectorAll("[data-passkey]").forEach(function (button) {
    if (!webauthn) { button.hidden = true; return; }
    button.addEventListener("click", unlockWithPasskey);
  });

  // ---- add a passkey (Settings) ---------------------------------------------
  var addForm = document.querySelector("[data-passkey-register]");
  if (addForm) {
    var addMsg = addForm.querySelector("[data-passkey-msg]");
    var addButton = addForm.querySelector("button");
    if (!webauthn) {
      addButton.disabled = true;
      if (addMsg) { addMsg.textContent = "This browser cannot create passkeys here."; }
    }
    addForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!webauthn) { return; }
      var data = new FormData();
      data.set("csrf_token", csrfOf(addForm));
      if (addMsg) { addMsg.textContent = "Follow the steps on your device…"; }
      post("/settings/passkeys/options", data).then(function (result) {
        if (!result.ok) { throw new Error("options"); }
        var o = result.json;
        return navigator.credentials.create({
          publicKey: {
            challenge: fromB64url(o.challenge),
            rp: o.rp,
            user: { id: fromB64url(o.user.id), name: o.user.name, displayName: o.user.displayName },
            pubKeyCredParams: o.pubKeyCredParams,
            timeout: o.timeout,
            attestation: o.attestation || "none",
            authenticatorSelection: o.authenticatorSelection,
            excludeCredentials: (o.excludeCredentials || []).map(function (c) {
              return { type: "public-key", id: fromB64url(c.id), transports: c.transports };
            })
          }
        });
      }).then(function (credential) {
        var data2 = new FormData(addForm);
        data2.set("credential", credentialJson(credential));
        return post("/settings/passkeys", data2);
      }).then(function (result) {
        if (result.ok) {
          window.location.assign(result.json.next || "/settings/security#lock");
        } else if (addMsg) {
          addMsg.textContent = result.json.error || "We could not add that passkey.";
        }
      }).catch(function () {
        if (addMsg) { addMsg.textContent = "No passkey was added."; }
      });
    });
  }
})();
