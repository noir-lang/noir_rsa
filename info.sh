(cd example && nargo compile --force --silence-warnings && bb gates -b ./target/example.json | grep "circuit")