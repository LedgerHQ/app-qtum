# Ledger Qtum Application

## Prerequisite

Be sure to have your environment correctly set up (see [Getting Started](https://developers.ledger.com/docs/nano-app/introduction/)) and [ledgerblue](https://pypi.org/project/ledgerblue/) installed.

If you want to benefit from [vscode](https://code.visualstudio.com/) integration, it's recommended to move the toolchain in `/opt` and set `BOLOS_ENV` environment variable as follows

```
BOLOS_ENV=/opt/bolos-devenv
```

and do the same with `BOLOS_SDK` environment variable

```
BOLOS_SDK=/opt/nanos-secure-sdk
```

## Compilation

```
make DEBUG=1  # compile optionally with PRINTF
make load     # load the app on the Nano using ledgerblue
```

## Documentation

High level documentation on the architecture and interface of the app:
- [qtum.md](doc/qtum.md): specifications of application commands.
- [wallet.md](doc/wallet.md): supported wallet signing policies.
- [merkle.md](doc/merkle.md): rationale and specifications for the usage of Merkle trees.

Additional documentation can be generated with [doxygen](https://www.doxygen.nl)

```
doxygen .doxygen/Doxyfile
```

the process outputs HTML and LaTeX documentations in `doc/html` and `doc/latex` folders.

## Client libraries

A [Python client library](bitcoin_client) and a [TypeScript client library](bitcoin_client_js) are available in this repository.

## Tests & Continuous Integration

The flow processed in [GitHub Actions](https://github.com/features/actions) is the following:

- Code formatting with [clang-format](http://clang.llvm.org/docs/ClangFormat.html)
- Compilation of the application for Ledger Nano S in [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder)
- Unit tests of C functions with [cmocka](https://cmocka.org/) (see [unit-tests/](unit-tests/))
- End-to-end tests with [Speculos](https://github.com/LedgerHQ/speculos) emulator (see [tests/](tests/))
- Code coverage with [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)/[lcov](http://ltp.sourceforge.net/coverage/lcov.php) and upload to [codecov.io](https://about.codecov.io)
- Documentation generation with [doxygen](https://www.doxygen.nl)

It outputs 4 artifacts:

- `qtum-app-debug` within output files of the compilation process in debug mode
- `code-coverage` within HTML details of code coverage
- `documentation` within HTML auto-generated documentation

## Develop on Ubuntu

This is a quick start script for developing app-qtum on Ubuntu.

    # Install docker
    sudo apt update
    sudo apt install snapd
    sudo snap refresh snapd
    sudo snap install docker
    sudo addgroup --system docker
    sudo adduser $USER docker
    newgrp docker
    sudo snap disable docker
    sudo snap enable docker
    
    # Pull the latest dev tool
    sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

    # Clone app-qtum
    sudo apt install git -y
    git clone https://github.com/qtumproject/app-qtum
    
    # Add rules for the supported devices
    sudo app-qtum/script/add_udev_rules.sh
    
    # Add ledger_env with command line to ~/.bashrc
    app-qtum/script/ledger_ubuntu_env.sh
    source ~/.bashrc
    
    # Build the ledger app
    cd app-qtum
    ledger_env
    make
    make load
    exit
