// Sign-in for a token-protected server. Served without credentials (it has to
// be) and so deliberately tiny: it trades the token for an httponly cookie via
// POST /api/login and then reloads into the real UI.
//
// A browser can arrive with the token in the URL *fragment* - /#token=... -
// which is never sent to a server, a proxy or in a Referer header. The query
// string is not accepted: it would land in logs and history.
(function () {
  "use strict";

  var form = document.getElementById("login");
  var input = document.getElementById("token");
  var message = document.getElementById("message");
  var button = form.querySelector("button");

  // Drop the fragment and any query string from the address bar and history.
  function clearUrl() {
    history.replaceState(null, "", location.pathname);
  }

  function say(text) {
    message.textContent = text;
  }

  async function signIn(token) {
    say("");
    button.disabled = true;
    try {
      var res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "NetForensicAI" },
        body: JSON.stringify({ token: token }),
      });
      if (res.ok) {
        location.replace(location.pathname);
        return;
      }
      var data = await res.json().catch(function () { return {}; });
      say(res.status === 429 ? data.error || "Too many attempts. Wait a moment and try again."
                             : "That token was not accepted.");
      input.select();
    } catch (err) {
      say("Could not reach the server.");
    } finally {
      button.disabled = false;
    }
  }

  var legacyQuery = /[?&]token=/.test(location.search);
  var fromFragment = null;
  try {
    var match = /(?:^#|&)token=([^&]*)/.exec(location.hash);
    if (match) fromFragment = decodeURIComponent(match[1]);
  } catch (err) {
    fromFragment = null; // malformed escape: fall back to the form
  }
  if (legacyQuery || location.hash) clearUrl();

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var token = input.value.trim();
    if (token) signIn(token);
  });

  if (fromFragment) {
    signIn(fromFragment);
  } else if (legacyQuery) {
    say("A token in the URL query string is no longer accepted. Paste it below instead.");
  }
})();
