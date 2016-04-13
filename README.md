# ndpi-scapy

A tool for fuzzy testing [nDPI](https://github.com/ntop/nDPI) library with the [scapy](http://www.secdev.org/projects/scapy) fuzzing tool.

This tool generates fake TCP and UDP traffic from current machine to the another (target) machine and plays it
on the real network. Ports, flags, body size and body content and randomized to provide
additional coverage for nDPI dissectors. ndpi-scapy starts and monitors `ndpiReader` instance and if it crashes saves a stack
trace, a description and PCAP file with the packet to the report and continues execution with the restarted `ndpiReader`.

Make sure you launch the tool on non-critical machine or network because simulated traffic can affect a network.
TCP traffic consists of SYN packets so a listening service or TCP stack at target machine usually just drops them
with RST packets. UDP traffic can be more real. Please check code and blacklist critical ports (22 ssh already blacklisted).

## Requirements

1. Python 2

2. scapy. Read installation [instructions](http://www.secdev.org/projects/scapy/doc/installation.html).
Example for CentOS 7:
  ```shell
  sudo yum install scapy pcapy
  ``` 

## Usage

1. Recompile nDPI and its example tool `ndpiReader` with address sanitizer support:
  ```shell
  CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common" \
    LDFLAGS="-fsanitize=address" ./autogen.sh
  make
  ```

2. Download `ndpi-scapy.py` script and launch as root: 
  ```shell
  python ndpi-scapy.py -t 192.168.1.100 -i enp0s3 -b ~/nDPI/example/ndpiReader -o ~/out --max-payload=50
  ```
  Here `-b` parameter points to nDPI example tool, `-o` specifies an output directory where ndpi-scapy.py stores reports
  and `-i` is your network interface. ndpi-scapy was not tested yet with loopback interface.

  All parameters can be found by launching with `--help` parameter.
  For example, `--restart` specifies an interval after which `ndpiReader` should be restarted.
  Parameters `--min-payload` and `--max-payload` specify a range of body payload.

3. Handy way to analyze collected logs is to use
[asan_symbolize.py](https://github.com/llvm-mirror/compiler-rt/blob/master/lib/asan/scripts/asan_symbolize.py)
script from the LLVM to mass-demangle stack traces:

  ```shell
  ls out/*error.log | xargs -L1 ./asan_symbolize.py -l | grep '#0.*nDPI'
  ```

  It prints all top-level functions where buffer overflows happened.

## Test launch

```shell
% python ndpi-scapy.py -t 192.168.1.100 -i enp0s3 -b ~/nDPI/example/ndpiReader -o ~/out --max-payload=50
[+] starting
[+] saving logs to: /home/user/out
[+] found logs: 0
............x...........x.......x...x..x....x.....x...x.x.xx.....x..x....x..x.......x..........xx.x.
[-] packets: 100 errors: 19
.............x...x......x.................................x.........x.x....x..xx...x................
[-] packets: 200 errors: 29
............x......x.........xx.x....x....x.x...........x.xx..x.........xxx..xx...x...........x.....
[-] packets: 300 errors: 48
..........x.x
^C
```

## License

MIT

