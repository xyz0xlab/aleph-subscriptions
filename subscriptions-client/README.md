Aleph zero chain client
=======================

This command line application provides a variety of tools to interact with the aleph zero chain, especially in the context of `Subscriptions` smart contract.

# Repository structure

This repository contains:

* `main.rs` - an executable
* `cli.rs` - command line application interface. Use `-h` option for the list of available commands

# Run aleph zero chain with Liminal extension

Clone [aleph zero github repository](git@github.com:Cardinal-Cryptography/aleph-node.git) and stay with `main` branch.

Run aleph network with liminal extension:

    $ cd aleph-node
    $ ./scripts/run_nodes.sh --liminal

Stop aleph network:

    $ killall -9 aleph-node
