
### Build the contract
```sh
cartesi build
```

### Run Cartesi node
```sh
cartesi run
```

Then in another terminal, run the following command to send the ciphertext to the contract:

### Send Ciphertext to the contract
```sh
cargo run --example send_call --target x86_64-unknown-linux-gnu > output
```