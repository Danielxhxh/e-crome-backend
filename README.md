# REST API and RUST IBE

The repository encompasses the backend of a project that ensures secure file transmissions through _Identity-Based Encryption_ (IBE) implemented in Rust, and further compiled into _WebAssembly_ (WASM) for usage within Node.js 

The repository is divided into two folders:
- rest-api
- rust


## Installation

Firstly, make sure you have the Rust programming language and the Node.js environment installed on your computer.

1. Compile the Rust code into WebAssembly (Wasm). Run these commands one by one:

```sh
# Navigate into the rust directory
cd rust

#Compile local packages and all of their dependencies.
cargo build

#Download and install a tool named 'wasm-pack'.
cargo install wasm-pack

#Compile the code to WebAssembly
wasm-pack build --target nodejs
```

2. Install all the required Node.js dependencies.

```sh
# Navigate into the rest-api folder
cd rest-api

# Install all the dependencies
npm install
```

## How to locally run the REST API.

Before running the project locally, ensure that you modify the _.env_ file according to your requirements. The file is located in _./rest-api/.env_.

To run the REST API execute the commands.
```sh
cd rest-api
npm run start
```

The REST API will be running on port 3000 if no other port is specified: 
```sh
127.0.0.1:3000
```

## License

MIT