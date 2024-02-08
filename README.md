# Disclaimer
This project's main purpose is to get hands dirty with rust myself, its tooling and libraries. Thus, there may be (and definitely will be) crutches, todos, nonoptimal/nonidiomatic code. Those are the goals to work on, along with the application itself. Application is not meant to be used by anyone.


# About
This is a transparent SSL proxy. 
It should be noted, that "transparent" is used in terms of [CONNECT driven tunnel](https://datatracker.ietf.org/doc/html/rfc2616#section-9.9). Thus, there is no need to ignore/or accept intermediate server SSL certificates. This is not a MitM HTTPS proxy. Client does not expose its sent/received data over HTTPS requests. Proxy transfers data as-is in tunnel-way without any introspection.

This can be used in common scenarios when tools allow it. e.g., curl, wget, python requests library, etc.

# Usage scenarios
## 1 Traffic redirect with a combination of SSH -R tunnel
This scenario is common for situations where there is a remote host (reachable via ssh) which requires but has no access to some external HTTPS resource, and at the same time, local machine do have such access.
Usually it is some bash/python/etc script deployed on some internet-restricted host.

Then there is a simple workaround with the ssh portforwading option + fibi-proxy.

Schematically, it looks like this:

<img src="/assets/readme/ssh-tun-combo-scheme.png" width="70%">

Step by step:

- 1. Establish a ssh tunnel to **remote_server** with port forwarding specifying local and remote ports. e.g.: 
```ssh -R 20000:localhost:10000 remote_host```
- 2. Start fibi-proxy at localhost, specifying the port for listening as 10000, e.g.: ```fibi-proxy -l 127.0.0.1:10000```
- 3. Run a resource-aware script on **remote_server** and specify (explicitly or via env configuration) a proxy address to the port created by the ssh tunnel in step 1, e.g.: ```curl -x localhost:20000 https://www.somer-resource.com```

There is an all-step illustration of a process video:

https://github.com/solc42/fibi-proxy/assets/19550062/a2ddbe9d-d9a8-4671-8069-a1d13d9cf4c6

## 2 Relay scenario
There is a mechanic that involves two nodes of application. The first node starts in relay mode, modifies traffic coming from the client, and transfers to the second node (with an explicit modification meta). The second node "rollbacks" data modification, and passes to the destination resource the original client data.
On the way back, traffic modifications are made in reverser order


Schematically, it looks like this:

<img src="/assets/readme/relay-scheme.png" width="70%">

## 3 Browser proxy
One can use proxy with browser plugins like [Container proxy](https://github.com/bekh6ex/firefox-container-proxy)(Firefox), [Switchy omega](https://github.com/FelisCatus/SwitchyOmega/blob/master/AUTHORS)(Chrome-like) or direct browser proxy configuration (reminder: only for HTTPS resources).

This scenario can be useful for loading variable traffic on an application to find bottlenecks/crashes under profiling tools.


# Help/CLI args
One can find at [CLI help test scenario](/tests/cli_args_data/stdout_help_long.txt)

# TODO(in any order)
## Testing
- Move proxy ["integrational" tests](/src/srv/server.rs) to real SSL server from the current tcp-stubs. Seems (hyper server example)[https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs] is enough for testing purposes.

- Figure out some libraries that respect the SSL connect tunnel-based proxy and not the MitM proxy for reducing dependency from system curl at [server.rs](/src/srv/server.rs)

## Performance
- Change naive read-once approach to accumulator-based with threshold at all places where **.read** used with markers about "partial read"

- Add timeout to connect/read/write points. It can be made in few keystrokes with [tokio::time::timeout wrapper](https://docs.rs/tokio/latest/tokio/time/fn.timeout.html), but thus it will be a bit ugly. It is better to find out what the idiomatic way - custom client struct wrapper or something else?

- Add requests limits. In-flight (semaphore?) and per time bucket. What to return to the user - HTTP 429?

## UX/UI
- Add UI. There is no valuable benefit, but [ratatui](https://github.com/ratatui-org/ratatui) is a great lib to become familiar with. Something htop-like, but way more primitive. Active Top-N, some groupping stats and orderings

## Telemetry/logs
- Integrate tracing subscribers to transfer data somewhere for visualization, mb [OpenTelemetry](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/)

- Elaborate more on the event/span/subscriber levels. Lucky there is a good new [video from Jon Gjengset on this topic](https://www.youtube.com/watch?v=21rtHinFA40) 

## Features
- Add relay command for scenarios with more tricky modifications. Not just in-place, but something like base64/aes - the main purpose is to add framing instruments to process packets that come from stream

- Add clasic HTTP proxy support. 

- Mb add authorization? One must read what kind of headers specify those mechanics by RFC

# Usefull links 
- [Wiki about HTTP tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel)
- [RFC link to CONNECT method](https://datatracker.ietf.org/doc/html/rfc2616#section-9.9)
