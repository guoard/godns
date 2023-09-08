# godns

This is a Go rewrite of the original [dnsguide](https://github.com/EmilHernvall/dnsguide) repository.

## Getting Started

Follow these steps to run the DNS server and test it:

### Run the DNS Server

Use the following command to start the DNS server:

```bash
go run main.go
```

The DNS server will listen on port 2053.

### Test the DNS Server

You can test the DNS server by running the `dig` command with the following syntax:

```bash
dig @127.0.0.1 -p 2053 google.com
```

This command queries the DNS server running on your local machine (`@127.0.0.1`) on port 2053 for the IP address of `google.com`.

## License

[MIT](./LICENSE)
