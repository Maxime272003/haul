// ==UserScript==
// @name         Haul — FuckingFast
// @namespace    haul.local
// @version      3.2
// @description  Envoie le lien de téléchargement FuckingFast à l'app Haul, qui télécharge hors du navigateur.
// @match        https://fuckingfast.co/*
// @match        https://www.fuckingfast.co/*
// @grant        GM_xmlhttpRequest
// @grant        window.close
// @connect      127.0.0.1
// @downloadURL  http://127.0.0.1:17655/haul.user.js
// @updateURL    http://127.0.0.1:17655/haul.user.js
// @run-at       document-idle
// @noframes
// ==/UserScript==

(function () {
  "use strict";

  const APP = "http://127.0.0.1:17655";
  // Secret propre à ton installation de Haul, exigé sur chaque requête. Il n'est pas écrit dans ce
  // script : on le demande à Haul (seule une extension peut lire la réponse), et on le redemande si
  // Haul le refuse. Rien à réinstaller quand il change.
  let token = null;
  const DIRECT_RE = /^https?:\/\/(?:dl\.fuckingfast\.co\/|(?:www\.)?fuckingfast\.co\/dl\/)/i;
  const LEGACY_RE = /window\.open\("(https?:\/\/(?:www\.)?fuckingfast\.co\/dl\/[^"]+)"\)/;

  if (location.pathname.startsWith("/dl/")) return;

  let state = "idle"; // idle -> sending -> done

  function banner(text, color) {
    let el = document.getElementById("haul-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "haul-banner";
      el.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;padding:10px 14px;" +
        "border-radius:8px;font:14px system-ui,sans-serif;color:#fff;box-shadow:0 2px 10px rgba(0,0,0,.3)";
      document.body.appendChild(el);
    }
    el.style.background = color;
    el.textContent = text;
  }

  function request(method, path, body, headers, onload, onerror) {
    GM_xmlhttpRequest({
      method,
      url: APP + path,
      headers,
      data: body === null ? undefined : JSON.stringify(body),
      timeout: 5000,
      onload(r) {
        if (r.status !== 200) return onerror(r.status);
        try { onload(JSON.parse(r.responseText)); } catch (e) { onerror(0); }
      },
      onerror() { onerror(0); },
      ontimeout() { onerror(0); },
    });
  }

  function withToken(then, onerror) {
    if (token) return then(token);
    request("GET", "/token", null, {}, (res) => { token = res.token; then(token); }, onerror);
  }

  function api(path, body, onload, onerror, retried) {
    withToken((t) => request("POST", path, body, { "Content-Type": "application/json", "X-Haul-Token": t },
      onload, (code) => {
        if (code === 401 && !retried) {  // jeton changé côté Haul : on le redemande une fois
          token = null;
          return api(path, body, onload, onerror, true);
        }
        onerror(code);
      }), onerror);
  }

  // fallback : appelé si l'app ne prend pas le lien (téléchargement normal dans le navigateur)
  function send(dlUrl, fallback) {
    if (state !== "idle") return;
    state = "sending";
    banner("Envoi à Haul…", "#555");
    api("/found", { page_url: location.href, dl_url: dlUrl, user_agent: navigator.userAgent }, (res) => {
      state = "done";
      banner("Lien envoyé à Haul ✔", "#1e7d34");
      if (res.close) setTimeout(() => window.close(), 800);
    }, (code) => {
      state = "idle";
      banner(code ? "Haul a refusé le lien (" + code + ")" : "Haul n'est pas lancé : téléchargement dans le navigateur",
        "#8a6d00");
      if (fallback) fallback();
    });
  }

  // Le bouton DOWNLOAD fait une requête htmx vers /f/<id>/go ; le lien direct revient dans l'en-tête HX-Redirect.
  // On l'intercepte avant que htmx ne redirige, pour que le navigateur ne télécharge pas lui-même.
  document.addEventListener("htmx:beforeOnLoad", (evt) => {
    const detail = (evt.wrappedJSObject || evt).detail; // wrappedJSObject : injection en mode « content » sous Firefox
    const xhr = detail && detail.xhr;
    const url = xhr && xhr.getResponseHeader("HX-Redirect");
    if (!url || !DIRECT_RE.test(url)) return;
    evt.preventDefault();
    send(url, () => { location.href = url; });
  }, true);

  // Ancienne version du site : lien écrit directement dans la page
  const legacy = document.documentElement.innerHTML.match(LEGACY_RE);
  if (legacy) return send(legacy[1]);

  // Pages ouvertes par l'app : on clique DOWNLOAD dès que le bouton est utilisable
  // (captcha validé par toi s'il y en a un).
  api("/wanted", { page_url: location.href }, (res) => {
    if (!res.wanted) {
      banner("Haul actif : clique sur DOWNLOAD pour envoyer le fichier à l'app", "#555");
      return;
    }
    banner("Haul : en attente du bouton (valide le captcha si demandé)…", "#555");
    const timer = setInterval(() => {
      if (state !== "idle") return clearInterval(timer);
      const btn = document.querySelector("a[hx-post], button[hx-post]");
      if (!btn) return;
      const widget = document.querySelector("#cf-turnstile, .cf-turnstile");
      const token = document.querySelector('[name="cf-turnstile-response"]');
      if (widget && !(token && token.value)) return; // captcha pas encore validé
      if (parseFloat(getComputedStyle(btn).opacity) < 0.9) return; // bouton pas encore actif
      clearInterval(timer);
      btn.click();
    }, 700);
  }, (code) => banner(code ? "Haul a refusé la requête (" + code + ")" : "Haul n'est pas lancé", "#8a6d00"));
})();
