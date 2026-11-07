/* Secureddy — "Ask Secureddy" chat. Progressive enhancement over plain
   forms: without this file every form posts and the page reloads.

   The answer streams in (Server-Sent Events from /assistant/stream over a
   fetch body, so the CSRF token travels in the form); Stop aborts it.

   Safety rule for this file: model output is never parsed as HTML. Replies
   and result cards are turned into DOM nodes with createElement +
   textContent only (a tiny markdown subset: paragraphs, line breaks,
   bullet/numbered lists, bold). Card links are same-origin paths the server
   built, and are checked to start with "/" before use. */
(function () {
  "use strict";

  var composer = document.getElementById("composer");
  var log = document.getElementById("chat-log");
  if (!composer || !log) {
    return;
  }
  var input = document.getElementById("composer-input");
  var typing = document.getElementById("typing");
  var sendButton = composer.querySelector("[data-send]") || composer.querySelector("button[type=submit]");
  var stopButton = composer.querySelector("[data-stop]");
  var statusLine = typing ? typing.querySelector("[data-status]") : null;
  var csrf = composer.getAttribute("data-csrf") || "";
  var busy = false;
  var controller = null;
  var canStream = !!(window.ReadableStream && window.TextDecoder && window.AbortController);

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

  // ---- result cards --------------------------------------------------------
  function safePath(value) {
    var href = String(value || "");
    return href.charAt(0) === "/" && href.charAt(1) !== "/" ? href : "";
  }

  function chipNode(chip) {
    var node = el("span", "chip tone-" + String((chip && chip.tone) || "grey").replace(/[^a-z]/g, ""));
    node.appendChild(el("span", null, chip && chip.label));
    return node;
  }

  function cardNode(c) {
    var kind = String(c.kind || "messages").replace(/[^a-z]/g, "");
    var card = el("div", "ccard ccard-" + kind);
    if (c.title) { card.appendChild(el("p", "ccard-title", c.title)); }
    if (kind === "link") {
      var box = el("div", "ccard-link");
      box.appendChild(chipNode(c.chip));
      box.appendChild(el("code", "url-text", c.url));
      box.appendChild(el("p", "muted small", (c.text || "") + (c.reason ? " " + c.reason : "")));
      if (c.downloads) { box.appendChild(el("p", "muted small", c.downloads)); }
      var href = safePath(c.href);
      if (href) { var a = el("a", "link", "Open the report"); a.href = href; box.appendChild(a); }
      card.appendChild(box);
    } else {
      var list = el(kind === "accounts" ? "ul" : "ol", "ccard-rows" + (kind === "ranked" ? " ccard-ranked" : ""));
      list.setAttribute("role", "list");
      (c.rows || []).forEach(function (r) {
        var li = el("li");
        var row = el("a", "ccard-row");
        var rowHref = safePath(r.href);
        if (rowHref) { row.href = rowHref; }
        if (r.rank) { row.appendChild(el("span", "ccard-rank", String(r.rank))); }
        var main = el("span", "ccard-main");
        if (kind === "accounts") {
          main.appendChild(el("strong", null, r.address));
          main.appendChild(el("span", "muted small", r.checked + " checked · " + r.flagged + " flagged this week"));
        } else {
          main.appendChild(el("strong", null, r.from));
          main.appendChild(el("span", "ccard-subject", r.subject));
          var meta = [r.reason, r.account, r.when].filter(function (x) { return !!x; }).join(" · ");
          main.appendChild(el("span", "muted small", meta));
        }
        row.appendChild(main);
        row.appendChild(chipNode(r.chip));
        li.appendChild(row);
        list.appendChild(li);
      });
      card.appendChild(list);
    }
    var more = safePath(c.more_href);
    if (more) { var m = el("a", "link ccard-more", "See all"); m.href = more; card.appendChild(m); }
    return card;
  }

  // ---- the bubble that is being written ------------------------------------
  function liveBubble() {
    var li = el("li", "bubble bubble-assistant bubble-live");
    li.appendChild(whoLabel());
    var draft = el("div", "bubble-body");
    var text = el("p", "bubble-draft");
    draft.appendChild(text);
    li.appendChild(draft);
    var cards = el("div", "bubble-cards");
    li.appendChild(cards);
    log.appendChild(li);
    return { li: li, body: draft, text: text, cards: cards, raw: "" };
  }

  function finishLive(live, reply, failed) {
    live.li.className = "bubble bubble-assistant" + (failed ? " bubble-failed" : "");
    if (reply && reply.id) { live.li.id = reply.id; }
    while (live.body.firstChild) { live.body.removeChild(live.body.firstChild); }
    renderMarkdown(live.body, reply ? reply.text : live.raw);
    if (reply && reply.cards && !live.cards.firstChild) {
      reply.cards.forEach(function (c) { live.cards.appendChild(cardNode(c)); });
    }
    if (!live.cards.firstChild && live.cards.parentNode) { live.cards.parentNode.removeChild(live.cards); }
    ((reply && reply.proposals) || []).forEach(function (p) { live.li.appendChild(proposalCard(p)); });
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
    (reply.cards || []).forEach(function (c) { li.appendChild(cardNode(c)); });
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
    if (statusLine && on) { statusLine.textContent = "Secureddy is looking…"; }
    if (sendButton) {
      sendButton.disabled = on;
      sendButton.hidden = on && !!stopButton;
    }
    if (stopButton) { stopButton.hidden = !on; }
    composer.setAttribute("aria-busy", on ? "true" : "false");
  }

  function setStatus(text) {
    if (statusLine && text) { statusLine.textContent = text; }
  }

  function afterFirstAnswer(json) {
    var idField = composer.querySelector("input[name=conversation_id]");
    if (idField && !idField.value && json.conversation_id) {
      idField.value = json.conversation_id;
      if (window.history && window.history.replaceState && safePath(json.conversation_url)) {
        window.history.replaceState(null, "", json.conversation_url);
      }
    }
    // The "about" email and the permission to read it belong to one question only.
    ["input[name=about]", ".composer-about-row"].forEach(function (sel) {
      var node = composer.querySelector(sel);
      if (node && node.parentNode) { node.parentNode.removeChild(node); }
    });
  }

  // ---- streaming -----------------------------------------------------------
  function parseEvents(buffer, onEvent) {
    var parts = buffer.split("\n\n");
    var rest = parts.pop();
    parts.forEach(function (block) {
      var name = "message";
      var data = [];
      block.split("\n").forEach(function (line) {
        if (line.indexOf("event:") === 0) { name = line.slice(6).trim(); }
        else if (line.indexOf("data:") === 0) { data.push(line.slice(5).replace(/^ /, "")); }
      });
      if (!data.length) { return; }
      var payload = {};
      try { payload = JSON.parse(data.join("\n")); } catch (e) { return; }
      onEvent(name, payload);
    });
    return rest;
  }

  function stream(data, live) {
    controller = new AbortController();
    var finished = false;
    var stopped = false;
    stopButton && (stopButton.onclick = function () { stopped = true; controller.abort(); });
    return fetch("/assistant/stream", {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: { Accept: "text/event-stream" },
      signal: controller.signal
    }).then(function (response) {
      var type = response.headers.get("content-type") || "";
      if (!response.ok || type.indexOf("text/event-stream") === -1 || !response.body) {
        return response.json().then(function (json) {
          if (response.status === 423 && json.unlock) { window.location.assign("/lock?next=" + encodeURIComponent(window.location.pathname)); }
          finishLive(live, { text: json.error || json.message || "Sorry, something went wrong. Please try again." }, true);
          finished = true;
        }, function () {
          finishLive(live, { text: "Sorry, something went wrong. Please try again." }, true);
          finished = true;
        });
      }
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";
      function onEvent(name, payload) {
        if (name === "start") { afterFirstAnswer(payload); }
        else if (name === "status") { setStatus(payload.text); }
        else if (name === "delta") { live.raw += payload.text || ""; live.text.textContent = live.raw; scrollToEnd(); }
        else if (name === "draft_done") { live.raw = ""; live.text.textContent = ""; }
        else if (name === "cards") { (payload.cards || []).forEach(function (c) { live.cards.appendChild(cardNode(c)); }); scrollToEnd(); }
        else if (name === "done") { afterFirstAnswer(payload); finishLive(live, payload.reply, payload.reply && payload.reply.failed); finished = true; }
        else if (name === "error") { finishLive(live, { text: payload.text }, true); finished = true; }
      }
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) {
            parseEvents(buffer + "\n\n", onEvent);
            return;
          }
          buffer = parseEvents(buffer + decoder.decode(chunk.value, { stream: true }), onEvent);
          return pump();
        });
      }
      return pump();
    }).catch(function () {
      if (!finished) {
        finishLive(live, { text: stopped ? (live.raw ? live.raw + "\n\n(Stopped.)" : "Stopped.") : "I could not reach Secureddy. Check your connection and try again." }, !stopped);
        finished = true;
      }
    }).then(function () {
      if (!finished) { finishLive(live, { text: live.raw || "Stopped." }, !live.raw); }
      controller = null;
    });
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
    if (canStream) {
      var live = liveBubble();
      scrollToEnd();
      stream(data, live).then(function () {
        setBusy(false);
        scrollToEnd();
        input.focus();
      });
      return;
    }
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
        afterFirstAnswer(json);
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

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && busy && controller) { controller.abort(); }
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
