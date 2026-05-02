FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
	build-essential \
	libpcap-dev \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY web_sniffer.cpp .

RUN g++ web_sniffer.cpp -o web_sniffer -lpcap

ENTRYPOINT ["./web_sniffer"]

