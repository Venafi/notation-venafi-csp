PORT=5001
IMAGE=net-monitor:v1
SIGNER="vsign-ztpki-rsa2048"

export NOTATION_EXPERIMENTAL=1

docker run -d -p $PORT:5000 --name orasregistrytest ghcr.io/oras-project/registry:v1.0.0-rc.4
docker build -t localhost:$PORT/$IMAGE https://github.com/wabbit-networks/net-monitor.git#main
docker push localhost:$PORT/$IMAGE

# sign
#notation sign -k $SIGNER --signature-manifest=image localhost:$PORT/$IMAGE
notation sign -d -v -k $SIGNER --signature-format=jws localhost:$PORT/$IMAGE

# verify
notation verify -d -v localhost:$PORT/$IMAGE

#sigscan repo localhost:$PORT --insecure --output pretty

# clean up
docker rm -f orasregistrytest
