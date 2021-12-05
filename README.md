# Famproxy

Famproxy is the family friendly proxy.

This is a proof of concept to block https traffic based on the SNI header.
Famproxy will sniff the SNI HTTPS headers to block or allow specific traffic.

## Usage

Start it up locally on port 6443:
```
cargo run
```

Route all outbound TLS traffic to 6443. (for testing use 5443 to avoid taking over all https traffic)
```
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dports 5443 -j REDIRECT --to-port 6443
sudo iptables -t nat -A PREROUTING -p tcp -m multiport --dports 5443 -j REDIRECT --to-port 6443
```

Try connect to google:
```
$ curl https://google.com:5443
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
```

Fail to connect to YouTube:
```
$ curl https://youtube.com:5443
curl: (35) OpenSSL SSL_connect: Connection reset by peer in connection to youtube.com:5443
```

Delete the rules when done:
```
sudo iptables -t nat -D OUTPUT -p tcp -m multiport --dports 5443 -j REDIRECT --to-port 6443
sudo iptables -t nat -D PREROUTING -p tcp -m multiport --dports 5443 -j REDIRECT --to-port 6443
```
