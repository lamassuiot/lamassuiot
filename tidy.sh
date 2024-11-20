DIR=$(pwd)

directories="
./core
./backend
./sdk
./aws
./engines/crypto/aws
./engines/crypto/filesystem
./engines/crypto/pkcs11
./engines/crypto/vaultkv2
./engines/eventbus/amqp
./engines/eventbus/aws
./engines/eventbus/channel
./engines/storage/couchdb
./engines/storage/postgres
./engines/storage/sqlite
./monolithic
./awsiotconnector
"

for dir in $directories; do
  # Skip empty lines
  if [ -n "$dir" ]; then
    echo "Tidying $dir"
    cd $DIR/$dir
    go mod tidy
  fi
done