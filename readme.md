Window1:
target/debug/./h3_test --listen 0.0.0.0:9876 --cert server.cert --key server.key

Window2:
curl -v "https://example.com:9876" --http3-only --resolve example.com:9876:127.0.0.1 -k
