export default {
  async fetch(request, env, ctx) {
    const get_or_head = ("GET" == request.method) || ("HEAD" == request.method);
    const worker_mirror_host = request.headers.get('Worker-Mirror-Host');

    const url = new URL(request.url);
    url.hostname = worker_mirror_host;

    const headers = new Headers(request.headers);
    headers.delete('Worker-Mirror-Host');
    headers.delete('CF-Connecting-IP');
    headers.delete('X-Forwarded-For');
    headers.delete('X-Real-IP');

    const modifiedRequest = new Request(url, {
      method: request.method,
      headers: headers,
      body: (get_or_head ? null : request.body),
      redirect: request.redirect,
    });

    return fetch(modifiedRequest);
  },
};
