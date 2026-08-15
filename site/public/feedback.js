// The Mosaic feedback widget. Every Mosaic product ships this same file, so a note or a bug
// report is one click from any page of any service and lands in one place.
//
// It is first-party on purpose: no third-party script, no cookies, no analytics, and nothing
// to loosen in a site's CSP beyond talking to our own endpoint.
(function () {
  // The pill is appended to <body>, which no framework here owns. The footer link is not:
  // a React site renders its own and asks for this one with data-footer-link, so nothing
  // is inserted into markup React will hydrate.
  var wantsFooterLink = !!(document.currentScript && document.currentScript.dataset.footerLink !== undefined);
  var ENDPOINT = "https://sandbox.mosaicos.com/v1/feedback";
  var SERVICES = {
    "sandbox.mosaicos.com": "Sandbox",
    "storage.mosaicos.com": "Object Storage",
    "memory.mosaicos.com": "Memory",
    "clickhouse.mosaicos.com": "ClickHouse®",
    "kafka.mosaicos.com": "Apache Kafka®",
    "observability.mosaicos.com": "Observability",
    "database.mosaicos.com": "Database",
  };

  if (document.querySelector(".feedback-pill")) return;

  var style = document.createElement("style");
  style.textContent = [
    ".feedback-pill{position:fixed;right:18px;bottom:18px;z-index:2147483000;appearance:none;border:1px solid rgba(255,255,255,.16);border-radius:999px;padding:10px 16px;font:600 13px/1 ui-sans-serif,system-ui,sans-serif;color:#e8efe6;background:#151a15;box-shadow:0 10px 30px rgba(0,0,0,.35);cursor:pointer}",
    ".feedback-pill:hover{background:#1d241c}",
    ".feedback-pill:focus-visible,.feedback-panel :focus-visible{outline:2px solid #a3e635;outline-offset:2px}",
    ".feedback-backdrop{position:fixed;inset:0;z-index:2147483001;background:rgba(0,0,0,.55);display:grid;place-items:end center;padding:18px}",
    ".feedback-backdrop[hidden]{display:none}",
    "@media(min-width:640px){.feedback-backdrop{place-items:center}}",
    ".feedback-panel{width:min(420px,100%);border:1px solid rgba(255,255,255,.14);border-radius:14px;background:#0f130f;color:#e8efe6;padding:18px;display:grid;gap:10px;box-shadow:0 24px 60px rgba(0,0,0,.5)}",
    ".feedback-panel h2{margin:0;font:800 16px/1.2 ui-sans-serif,system-ui,sans-serif}",
    ".feedback-panel p{margin:0;font:400 12px/1.5 ui-sans-serif,system-ui,sans-serif;color:#9ba298}",
    ".feedback-panel label{font:600 11px/1.4 ui-sans-serif,system-ui,sans-serif;text-transform:uppercase;letter-spacing:.1em;color:#9ba298}",
    ".feedback-panel textarea,.feedback-panel input{width:100%;box-sizing:border-box;border:1px solid rgba(255,255,255,.16);border-radius:8px;background:#0a0d0a;color:#e8efe6;padding:9px;font:400 13px/1.5 ui-sans-serif,system-ui,sans-serif}",
    ".feedback-panel textarea{min-height:110px;resize:vertical}",
    ".feedback-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:2px}",
    ".feedback-actions button{appearance:none;border-radius:8px;padding:8px 14px;font:600 13px/1 ui-sans-serif,system-ui,sans-serif;cursor:pointer}",
    ".feedback-cancel{border:1px solid rgba(255,255,255,.16);background:transparent;color:#e8efe6}",
    ".feedback-send{border:1px solid #a3e635;background:#a3e635;color:#101510}",
    ".feedback-send[disabled]{opacity:.6;cursor:progress}",
    ".feedback-status{font:400 12px/1.5 ui-sans-serif,system-ui,sans-serif;min-height:18px}",
    ".feedback-status[data-tone=error]{color:#ff8f8f}",
    ".feedback-status[data-tone=ok]{color:#a3e635}",
  ].join("");
  document.head.append(style);

  var pill = document.createElement("button");
  pill.type = "button";
  pill.className = "feedback-pill";
  pill.textContent = "Feedback";
  pill.setAttribute("aria-haspopup", "dialog");

  var backdrop = document.createElement("div");
  backdrop.className = "feedback-backdrop";
  backdrop.hidden = true;

  var panel = document.createElement("form");
  panel.className = "feedback-panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "true");
  panel.setAttribute("aria-labelledby", "feedback-title");

  var title = document.createElement("h2");
  title.id = "feedback-title";
  title.textContent = "Send us a note";
  var blurb = document.createElement("p");
  blurb.textContent = "Bug, confusion, or a request — it reaches the people building this. We attach the page you are on.";

  var messageLabel = document.createElement("label");
  messageLabel.htmlFor = "feedback-message";
  messageLabel.textContent = "What happened";
  var message = document.createElement("textarea");
  message.id = "feedback-message";
  message.required = true;
  message.maxLength = 4000;

  var emailLabel = document.createElement("label");
  emailLabel.htmlFor = "feedback-email";
  emailLabel.textContent = "Email (optional, so we can reply)";
  var email = document.createElement("input");
  email.id = "feedback-email";
  email.type = "email";
  email.autocomplete = "email";

  var status = document.createElement("p");
  status.className = "feedback-status";
  status.setAttribute("role", "status");

  var actions = document.createElement("div");
  actions.className = "feedback-actions";
  var cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "feedback-cancel";
  cancel.textContent = "Cancel";
  var send = document.createElement("button");
  send.type = "submit";
  send.className = "feedback-send";
  send.textContent = "Send";
  actions.append(cancel, send);

  panel.append(title, blurb, messageLabel, message, emailLabel, email, status, actions);
  backdrop.append(panel);

  var lastFocused = null;

  function open() {
    lastFocused = document.activeElement;
    backdrop.hidden = false;
    status.textContent = "";
    message.focus();
  }

  function close() {
    if (backdrop.hidden) return;
    backdrop.hidden = true;
    if (lastFocused && lastFocused.focus) lastFocused.focus();
  }

  pill.addEventListener("click", open);
  cancel.addEventListener("click", close);
  backdrop.addEventListener("mousedown", function (event) {
    if (event.target === backdrop) close();
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") close();
  });

  // A modal that lets focus wander behind it is a modal in name only, and the panel is small
  // enough that cycling its own focusables is the whole of it.
  panel.addEventListener("keydown", function (event) {
    if (event.key !== "Tab") return;
    // Send is switched off while a report is in flight; keeping it in the cycle would strand
    // a keyboard user on Cancel, since focusing a disabled button does nothing but Tab is eaten.
    var focusable = [message, email, cancel, send].filter(function (element) { return !element.disabled; });
    var index = focusable.indexOf(document.activeElement);
    var next = event.shiftKey ? index - 1 : index + 1;
    if (next < 0) next = focusable.length - 1;
    if (next >= focusable.length) next = 0;
    if (index !== -1) {
      event.preventDefault();
      focusable[next].focus();
    }
  });

  panel.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!message.value.trim()) {
      status.dataset.tone = "error";
      status.textContent = "Tell us what happened — a sentence is enough.";
      message.focus();
      return;
    }
    // Disabling the button the user just pressed blurs it to <body>, which puts focus outside
    // the panel and out of reach of the Tab cycle below, so hand it to Cancel first.
    if (document.activeElement === send) cancel.focus();
    send.disabled = true;
    status.dataset.tone = "";
    status.textContent = "Sending…";

    fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: message.value,
        email: email.value,
        page_url: location.href,
        service: SERVICES[location.hostname] || location.hostname,
      }),
    })
      // An edge error page or an empty body is not JSON, and a parser's complaint about a
      // "<" is no use to someone reporting a bug: read it as text and fall back to our words.
      .then(function (response) {
        return response.text().then(function (body) {
          try {
            return { ok: response.ok, body: body ? JSON.parse(body) : null };
          } catch {
            return { ok: response.ok, body: null };
          }
        });
      })
      .then(function (result) {
        if (!result.ok) throw new Error(result.body && result.body.message ? result.body.message : "We could not send that.");
        status.dataset.tone = "ok";
        status.textContent = "Thank you — it is filed.";
        message.value = "";
        setTimeout(close, 1200);
      })
      .catch(function (error) {
        status.dataset.tone = "error";
        // Nobody should retype a paragraph because our endpoint blinked, so the message stays.
        status.textContent = error.message + " Mail hello@mosaicos.com if this keeps happening.";
      })
      .finally(function () {
        send.disabled = false;
      });
  });

  document.body.append(pill, backdrop);

  // So a site that renders its own footer link can open the same panel.
  window.mosaicFeedback = { open: open, close: close };

  // A footer link for people who look there rather than at the corner.
  var footer = wantsFooterLink ? document.querySelector("footer") : null;
  if (footer && !footer.querySelector(".feedback-footer-link")) {
    var link = document.createElement("button");
    link.type = "button";
    link.className = "feedback-footer-link";
    link.textContent = "Feedback";
    link.style.cssText = "appearance:none;border:0;background:none;padding:0;font:inherit;color:inherit;text-decoration:underline;cursor:pointer";
    link.addEventListener("click", open);
    footer.append(document.createTextNode(" "), link);
  }
})();
