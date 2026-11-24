/* Every change the page asks the server for (anything but GET) carries the value of the peakcut_csrf cookie in an
   X-CSRF-Token header. Another website can make a browser send the cookie, but it cannot read it, so it cannot add
   the header: the server refuses its requests. Loaded first on every page, so every fetch and upload gets it. */
(() => {
  const token = () => (document.cookie.match(/(?:^|;\s*)peakcut_csrf=([^;]+)/) || [])[1] || "";
  const changes = m => !/^(GET|HEAD|OPTIONS)$/i.test(m || "GET");
  const ours = u => { try { return new URL(u, location.href).origin === location.origin; } catch { return false; } };
  const plainFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const isReq = typeof Request !== "undefined" && input instanceof Request;
    const method = init.method || (isReq ? input.method : "GET"), url = isReq ? input.url : String(input);
    if (changes(method) && ours(url)) {
      const h = new Headers(init.headers || (isReq ? input.headers : undefined));
      h.set("X-CSRF-Token", token());
      init = {...init, headers: h};
    }
    return plainFetch(input, init);
  };
  const open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) { this._pcMethod = method; this._pcUrl = url; return open.call(this, method, url, ...rest); };
  XMLHttpRequest.prototype.send = function (body) {
    if (changes(this._pcMethod) && ours(this._pcUrl)) this.setRequestHeader("X-CSRF-Token", token());
    return send.call(this, body);
  };
})();
