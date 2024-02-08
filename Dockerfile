FROM rust:1.76.0-slim-bookworm as builder
WORKDIR /app
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update \
        && apt-get install -y htop \
	curl \
	tzdata \
	lsof \
	strace \
	ncdu \
	iputils-ping \
	traceroute \
	netcat-traditional \
	telnet \
	net-tools \
	dnsutils \
	iproute2 \
	lsb-release \
	&& apt-get autoremove -y \
	&& apt-get clean -y \
	&& rm -rf /var/lib/apt/lists/*

# those two add about 70mb
# linux-perf
# ntp

COPY --from=builder /usr/local/cargo/bin/fibi-proxy /usr/local/bin/fibi-proxy

ENTRYPOINT ["fibi-proxy"]
CMD [""]
