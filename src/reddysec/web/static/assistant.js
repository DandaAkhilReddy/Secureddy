/* Secureddy — "Ask Secureddy" chat. Progressive enhancement over plain
   forms: without this file every form posts and the page reloads.

   Safety rule for this file: model output is never parsed as HTML. Replies
   are turned into DOM nodes with createElement + textContent only (a tiny
   markdown subset: paragraphs, line breaks, bullet/numbered lists, bold). */
(function () {
  "use strict";

  var composer = document.getElementById("composer");
  var log = document.getElementById("chat-log");
  if (!composer || !log) {
    return;
  }
  var input = document.getElementById("composer-input");
  var typing = document.getElementById("typing");
  var sendButton = composer.querySelector("button[type=submit]");
  var csrf = composer.getAttribute("data-csrf") || "";
  var busy = false;

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = text;
    }
    return node;
  }

  // ---- minimal markdown, DOM only -------------------------------------
  function appendSegments(parent, line) {
    var parts = line.split("**");
    if (parts.length % 2 === 0) {
      parent.appendChild(document.createTextNode(line));
      return;
    }
    parts.forEach(function (part, i) {
      if (!part) {
        return;
      }
      if (i % 2 === 1) {
        parent.appendChild(el("strong", null, part));
      } else {
        parent.appendChild(document.createTextNode(part));
      }
    });
  }

  var LIST_ITEM = /^\s*(?:[-*•]|(\d{1,2})[.)])\s+(.*)$/;

  function renderMarkdown(container, text) {
    var chunks = String(text || "").replace(/\r\n/g, "\n").split(/\n\n+/);
    chunks.forEach(function (chunk) {
      var current = null;
      var currentType = "";
      chunk.split("\n").forEach(function (raw) {
        if (!raw.trim()) {
          return;
        }
        var m = LIST_ITEM.exec(raw);
        if (m) {
          var type = m[1] ? "ol" : "ul";
          if (!current || currentType !== type) {
            current = el(type);
            currentType = type;
            container.appendChild(current);
          }
          var li = el("li");
          appendSegments(li, m[2].trim());
          current.appendChild(li);
        } else {
          var line = raw.trim().replace(/^#+\s*/, "");
          if (!current || currentType !== "p") {
            current = el("p");
            currentType = "p";
            container.appendChild(current);
          } else {
            current.appendChild(el("br"));
          }
          appendSegments(current, line);
        }
      });
    });
  }

  // ---- bubbles ---------------------------------------------------------
  function whoLabel() {
    var who = el("span", "bubble-who");
    var tmpl = document.querySelector(".bubble-who svg");
    if (tmpl) {
      who.appendChild(tmpl.cloneNode(true));
    }
    who.appendChild(document.createTextNode("Secureddy"));
    return who;
  }

  function addUserBubble(text) {
    var li = el("li", "bubble bubble-user");
    var body = el("div", "bubble-body");
    body.appendChild(el("p", null, text));
    li.appendChild(body);
    log.appendChild(li);
    return li;
  }

  function hiddenInput(name, value) {
    var input = el("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    return input;
  }

  function proposalCard(p) {
    var card = el("div", "proposal proposal-" + p.tone + " proposal-" + p.status);
    var title = el("p", "proposal-title");
    title.appendChild(el("span", null, p.title));
    card.appendChild(title);
    var mail = el("div", "proposal-mail");
    var senderLine = el("span", "proposal-sender", p.sender);
    if (p.address && p.address !== p.sender) {
      senderLine.appendChild(document.createTextNode(" "));
      senderLine.appendChild(el("span", "muted", p.address));
    }
    mail.appendChild(senderLine);
    var subject = el("a", "proposal-subject", p.subject);
    subject.href = p.report; // a same-origin path built by the server, never model text
    mail.appendChild(subject);
    card.appendChild(mail);
    if (p.reason) {
      card.appendChild(el("p", "proposal-reason", p.reason));
    }
    if (p.status !== "open") {
      card.appendChild(el("p", "proposal-status", p.status_text));
      return card;
    }
    var actions = el("div", "proposal-actions");
    var yes = el("form");
    yes.method = "post";
    yes.action = p.action;
    yes.appendChild(hiddenInput("csrf_token", csrf));
    yes.appendChild(hiddenInput("next", p.next));
    if (p.send_reason) {
      yes.appendChild(hiddenInput("reason_code", "assistant"));
    }
    var yesButton = el("button", "btn btn-small " + (p.kind === "mark_fake" ? "btn-danger-solid" : "btn-primary"), p.yes);
    yesButton.type = "submit";
    yes.appendChild(yesButton);
    var no = el("form");
    no.method = "post";
    no.action = p.decline_action;
    no.setAttribute("data-decline", "");
    no.appendChild(hiddenInput("csrf_token", csrf));
    no.appendChild(hiddenInput("reply_id", p.reply_id));
    no.appendChild(hiddenInput("index", String(p.index)));
    var noButton = el("button", "btn btn-small btn-quiet", "No");
    noButton.type = "submit";
    no.appendChild(noButton);
    wireDecline(no);
    actions.appendChild(yes);
    actions.appendChild(no);
    card.appendChild(actions);
    return card;
  }

  function addAssistantBubble(reply, failed) {
    var li = el("li", "bubble bubble-assistant" + (failed ? " bubble-failed" : ""));
    if (reply.id) {
      li.id = reply.id;
    }
    li.appendChild(whoLabel());
    var body = el("div", "bubble-body");
    renderMarkdown(body, reply.text);
    li.appendChild(body);
    (reply.proposals || []).forEach(function (p) {
      li.appendChild(proposalCard(p));
    });
    log.appendChild(li);
    return li;
  }

  function scrollToEnd() {
    var last = log.lastElementChild;
    if (last && last.scrollIntoView) {
      last.scrollIntoView({ block: "end" });
    }
  }

  function setBusy(on) {
    busy = on;
    if (typing) {
      typing.hidden = !on;
    }
    if (sendButton) {
      sendButton.disabled = on;
    }
    composer.setAttribute("aria-busy", on ? "true" : "false");
  }

  // ---- sending -----------------------------------------------------------
  function send(text) {
    text = String(text || "").trim();
    if (!text || busy) {
      return;
    }
    var welcome = log.querySelector(".bubble-welcome");
    var suggest = document.querySelector("[data-suggest]");
    if (suggest && suggest.parentNode) {
      suggest.parentNode.removeChild(suggest);
    }
    if (welcome && welcome.parentNode) {
      welcome.parentNode.removeChild(welcome);
    }
    addUserBubble(text);
    var data = new FormData(composer);
    data.set("message", text);
    input.value = "";
    autosize();
    setBusy(true);
    scrollToEnd();
    fetch(composer.action, {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.json().then(
          function (json) { return { ok: response.ok, json: json }; },
          function () { return { ok: false, json: {} }; }
        );
      })
      .then(function (result) {
        if (!result.ok || !result.json.reply) {
          addAssistantBubble({ text: result.json.error || "Sorry, something went wrong. Please try again." }, true);
          return;
        }
        var json = result.json;
        var idField = composer.querySelector("input[name=conversation_id]");
        if (idField && !idField.value) {
          idField.value = json.conversation_id;
          if (window.history && window.history.replaceState) {
            window.history.replaceState(null, "", json.conversation_url);
          }
        }
        // The "about" context belongs to the first question only.
        var about = composer.querySelector("input[name=about]");
        if (about && about.parentNode) {
          about.parentNode.removeChild(about);
        }
        addAssistantBubble(json.reply, json.reply.failed);
      })
      .catch(function () {
        addAssistantBubble({ text: "I could not reach Secureddy. Check your connection and try again." }, true);
      })
      .then(function () {
        setBusy(false);
        scrollToEnd();
        input.focus();
      });
  }

  composer.addEventListener("submit", function (event) {
    event.preventDefault();
    send(input.value);
  });

  input.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      send(input.value);
    }
  });

  function autosize() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 200) + "px";
  }
  input.addEventListener("input", autosize);

  var suggestions = document.querySelector("[data-suggest]");
  if (suggestions) {
    suggestions.addEventListener("click", function (event) {
      var button = event.target.closest ? event.target.closest("button[name=message]") : null;
      if (button) {
        event.preventDefault();
        send(button.value);
      }
    });
  }

  // ---- "No" on a proposal ----------------------------------------------
  function wireDecline(form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      }).then(function (response) {
        if (!response.ok) {
          return;
        }
        var card = form.closest(".proposal");
        var actions = form.closest(".proposal-actions");
        if (card && actions) {
          card.className = card.className.replace("proposal-open", "proposal-declined");
          actions.parentNode.replaceChild(el("p", "proposal-status", "You said no. Nothing changed."), actions);
        }
      });
    });
  }
  document.querySelectorAll("form[data-decline]").forEach(wireDecline);

  scrollToEnd();
})();
