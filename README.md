Heavily work-in-progress rewrite of OpenBSD's `doas` in Rust

Largely based on [Ted Unangst](https://flak.tedunangst.com/post/doas)'s work.

## About the project

`dosu` is **not** an official OpenBSD project/port!

Even though I have done my due dilligence to ensure quality code, there are likely still things I've missed.

So far, this is a one-person development project with no peer review, in the earliest stages of development.

Please be careful when using `dosu`.

## Building and installing

To download and build `dosu`:

```sh
:$ git clone https://github.com/orvij/dosu
:$ cd dosu
:$ cargo build --release

## If you want to play around with dosu before installing,
## you need to change ownership to root and setuid

:# chown root:bin target/release/dosu
:# chmod 4555 target/release/dosu
```

To install `dosu`:

```sh
## Basic install script to make dosu setuid, and install to the correct path
## Proper "make install" script is WIP, and current script is non-portable

:$ ./install 
:$ ./install /usr/local/bin
```

Running `dosu` is should be very familiar to anyone using `doas`:

```sh
:$ dosu ls
:$ dosu -s
:$ dosu -C /etc/doas.conf
:$ dosu du -a
:$ dosu -h
```

## Porting to non-OpenBSD systems

Much like the work in [OpenDoas](https://github.com/Duncaen/OpenDoas), the long-term goal of this project is to be portable across as many systems as possible.

Currently, only OpenBSD is supported. The next OS targets are (in no particular order):

- NetBSD
- DragonflyBSD
- FreeBSD
- Linux
- Windows?
- MacOS?
- Phone OSes?

If you have an operating system you would like `dosu` to support, please file an issue or submit some code, and it will get added to the list.

## Removing reliance on unsafe

`dosu` needs to interact with the operating system, since it's basically just glue code around a few system calls.

There are a number of places where calling a C FFI is unavoidable, in the main code and dependencies.

It is a long-term goal to remove as much `unsafe` as possible. Who knows, maybe one day all system calls will be in Rust 😉

## Credits

A huge thank you to Ted Unangst and the OpenBSD devs for the high-quality code and documentation. Really helped in porting, and likely saved countless hours in debugging.

A similar sized gesture of gratitude to the Rust devs for making the coding experience so great, the [libc](https://github.com/rust-lang/libc) and [nix](https://github.com/nix-rust/nix) devs for their work on C FFI interfaces, the [nom](https://github.com/Geal/nom) devs for their parser work, and Josh Triplett and Joshua Nelson for helping debug documentation builds.

## Bugs

`dosu` is still very much a work-in-progress, and likely has bugs.

While I've done my best to ensure high-quality code, bugs are almost certainly present.

If you find something, please open an issue and/or submit a fix.
