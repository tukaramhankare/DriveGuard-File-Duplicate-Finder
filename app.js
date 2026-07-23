// DriveGuard landing page — copy-to-clipboard for the command snippets.
// No other interactivity on this page by design; the download link and
// GitHub link are plain anchors and work with JavaScript disabled too.

document.addEventListener("DOMContentLoaded", function () {
  var buttons = document.querySelectorAll(".copy-btn");

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetId = btn.getAttribute("data-copy-target");
      var target = targetId ? document.getElementById(targetId) : null;
      if (!target) return;

      var text = target.textContent;

      copyText(text).then(function (ok) {
        var original = btn.textContent;
        btn.textContent = ok ? "Copied" : "Copy failed";
        btn.classList.toggle("is-copied", ok);
        window.setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("is-copied");
        }, 1800);
      });
    });
  });

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(
        function () { return true; },
        function () { return fallbackCopy(text); }
      );
    }
    return Promise.resolve(fallbackCopy(text));
  }

  function fallbackCopy(text) {
    // Works on http:// / file:// contexts where navigator.clipboard is
    // unavailable (it requires a secure context).
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(textarea);
    return ok;
  }
});
