addEventListener(
  'fetch', event => {
    const worker_mirror_host = event.request.headers.get('Worker-Mirror-Host');
    const url = new URL(event.request.url);
    url.hostname = worker_mirror_host;

    const modifiedRequest = new Request(url, {
      body: event.request.body,
      headers: event.request.headers,
      method: event.request.method,
      redirect: event.request.redirect
    });

    modifiedRequest.headers.delete('Worker-Mirror-Host');
    modifiedRequest.headers.delete('CF-Connecting-IP');
    modifiedRequest.headers.delete('X-Forwarded-For');
    modifiedRequest.headers.delete('X-Real-IP');

    const request = new Request(url, modifiedRequest);
    event.respondWith(fetch(request));
  }
)
