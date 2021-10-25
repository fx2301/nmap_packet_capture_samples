# nmap packet capture samples

The `scan_host.py` script can be used to enumerate `nmap` commands against a host. It uses tcpdump to capture the resulting traffic.

As a bonus, verbose output from nmap is included alongside each `pcap` file.

## Hosts sampled

Packet captures are included for two retired hosts from [Hack The Box](https://hackthebox.eu):

* [dynstr](https://app.hackthebox.eu/machines/dynstr) - see all filenames containing `10.10.10.244` in the [data](https://github.com/fx2301/nmap_packet_capture_samples/tree/master/data) directory.
* [Return](https://app.hackthebox.eu/machines/Return) - see all filenames containing `10.10.11.108` in the [data](https://github.com/fx2301/nmap_packet_capture_samples/tree/master/data) directory.

## Scan types

`nmap` provides these scan types:

```
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
```

All of the above except for Maimon (FIN/ACK), Idle, IP protocol and FTP bounce scan are enumerated.

For `--scanflags` a single, likely most interesting, combination is enumerated: `--scanflags SYNFIN`.

## Ports scanning

The top 1000 ports are scanned for all scan techniques (with the exception of UDP which is limited to 100 ports for speed).

## Version scanning

Each host and scan type has a packet capture with version scanning (`-sV`) and without. The exception is TCP ACK scanning (`-sA`) which excludes `rpc-grind.nse` due a port conflict.
