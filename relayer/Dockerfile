FROM node:22-slim

# Install stellar CLI
RUN apt-get update && apt-get install -y curl ca-certificates libdbus-1-3 && \
    curl -sSL https://github.com/stellar/stellar-cli/releases/download/v23.4.1/stellar-cli-23.4.1-aarch64-unknown-linux-gnu.tar.gz \
    | tar -xz -C /usr/local/bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json server.js ./

COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 3000

ENV STELLAR_ACCOUNT=relayer
ENV WALLET_CONTRACT=CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B

CMD ["./entrypoint.sh"]
