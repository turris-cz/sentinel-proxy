# Dev proxy

It is proxy emulation for development purposes.
It just prints all received messages from given ZMQ socket to stdout.

## Run

```
./dev/dev_proxy.py [options]
```

Options:
- `-s` / `--socket`: path of ZMQ socket to listen on,
  default is: `ipc:///tmp/sentinel_pull.sock`

## Minipots testing

There is also bash script `run_dev_proxy_for_minipots.sh` intended for
quick test setup of Minipots component. It is companion of
`run_minipots_for_tests.sh` script in Minipots repository.

It must have one argument specifying
type of minipot for testing:
- `f`/`h`/`s`/`t` - meaning FTP, HTTP, SMTP, Telnet minipot
- `T` - This is meant for throughput testing

**Example:**

```
cd dev/
./run_dev_proxy_for_minipots.sh f
```
It runs `dev_proxy` for manual testing of FTP minipot without need to remember
and specify `-s` option for `dev_proxy`, which would be needed without using
the script.
