#!/bin/sh

cargo build --release --locked --target x86_64-unknown-linux-musl
rsync target/x86_64-unknown-linux-musl/release/geph4-binder root@binder.infra.geph.io:/usr/local/bin/
ssh root@binder.infra.geph.io systemctl restart geph4-binder
