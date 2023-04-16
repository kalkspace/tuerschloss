# README

Softwaregefrickel für's neue Türschloss.

## Develop outside of Linux

### macOS

First, install the Rust target to build for Linux:

```
rustup target add x86_64-unknown-linux-gnu
```

Next, install the pcsc library via Homebrew:

```
brew install pcsc-lite
```

You can put this into your user-wide settings to allow rust-analyzer to work:

```json
{
  "rust-analyzer.cargo.extraEnv": {
    "PCSC_LIB_DIR": "/opt/homebrew/opt/pcsc-lite/lib",
  }
}
```

To run clippy locally, run this command:

```
PCSC_LIB_DIR=$(brew --prefix)/opt/pcsc-lite/lib PKG_CONFIG_ALLOW_CROSS=1 cargo clippy --target x86_64-unknown-linux-gnu
```
