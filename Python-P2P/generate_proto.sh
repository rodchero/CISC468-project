#!/bin/bash
# Generate Python protobuf code from our .proto file
# Run this from the Python-P2P/ directory

cd "$(dirname "$0")"

python -m grpc_tools.protoc \
    -I./proto \
    --python_out=./src/generated \
    ./proto/p2pfileshare.proto

echo "Proto generation done."
