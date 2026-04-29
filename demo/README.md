# macchk browser demo

Small Rsbuild/Rspack demo for running the WASM analyzer in a browser. It accepts
a Mach-O file via drag and drop or the file picker, then renders the check
summary.

## Prerequisites

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.118
```

## Commands

```sh
npm install
npm run dev
npm run build
npm run preview
```

The `build:wasm` script compiles the Rust library with the `wasm` feature and
writes generated bindings to `src/pkg/`. That directory is intentionally ignored
because it is recreated by the demo build.

The `typecheck` script uses `tsgo` from `@typescript/native-preview` so the
TypeScript validation path is native rather than the JavaScript `tsc` compiler.
