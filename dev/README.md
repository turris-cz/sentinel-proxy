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
