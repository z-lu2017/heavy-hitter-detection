# Implementing Hula

## Introduction

The objective of this tutorial is to implement a simplified version of
[HULA](http://web.mit.edu/anirudh/www/hula-sosr16.pdf). In contrast to
ECMP, which selects the next hop randomly, HULA load balances the
flows over multiple paths to a destination ToR based on queue
occupancy of switches in each path. Thus, it can use the whole
bisection bandwidth.  To keep the example simple, we implement it on
top of source routing exercise.

Here is how HULA works:

* Each ToR switch generates a HULA packet to each other ToR switch for
  each path between source and destination ToR.  The packets go to the
  destination ToR (forward path) and may come back to the source ToR
  (reverse path) if they change the best path.  The packets include a
  HULA header and a list of ports for source routing.  We describe the
  elements of HULA header later.  The source routing port list has the
  ports for going to the distination ToR on the specific path and then
  returning back to the source ToR (on the same path).

* On the forward path:
 - Each hop updates the queue length field in the HULA header at egress
   if it is smaller than observed queue length at that switch. Thus
   when the packet reaches the destination ToR, queue length field
   will be the maximum observed queue length.   
  - At the destination ToR, 
    1. Find the queue length of current best path from the source ToR
    2. If the new path is better, update the queue length and best
       path and return HULA packet to the source path. This is done by
       setting the direction field in the HULA header and returning
       the packet to the ingress port.
    3. If the packet came from the current best path, just update the
     value.  This is to know if the best path got worse and allows
     other paths to replace it later.  It is inefficient to save the
     whole path and compare it in the data plane.  Instead, we keep a
     32 bit digest of path in the HULA header. Each destination ToR,
     only saves and compares the digest of the best path along with
     its queue length.  The `hula.digest` field is set by source ToR
     upon creating the HULA packet and does not change along the path.     
* On the reverse path:
 - Each hop will update the "routing next hop" to the destination ToR
   based on the port it received HULA packet on (as it was the best
   path). Then it forwards the packet to next hop in reverse path
   based on source routing.
 - The source ToR also drops the packet.
 - In addition, for each data packet,
  - Each hop, hashes the flow header fields and looks into a "flow table".  
  - If it doesn't find the next hop for the flow, looks for "routing
    next hop" to find the next hop for destination ToR. We assume each
    ToR serves a /24 IP address.  The switch also updates "flow
    table". "flow table" prevents changing the path for a flow in
    order to avoid packet re-ordering and path oscilation during
    updating next hops.
  - Otherwise just use the next hop.

Your switch will have multiple tables, which the control plane will
populate with static rules. We have already defined the control plane
rules, so you only need to implement the data plane logic of your P4
program.

> **Spoiler alert:** There is a reference solution in the `solution`
> sub-directory. Feel free to compare your implementation to the reference.

## Step 1: Run the (incomplete) starter code

The directory with this README also contains a skeleton P4 program,
`hula.p4`, which initially drops all packets.  Your job (in the next
step) will be to extend it to properly update HULA packets and forward
data packets.

Before that, let's compile the incomplete `hula.p4` and bring up a
switch in Mininet to test its behavior.

1. In your shell, run:
   ```bash
   ./run.sh
   ```
   This will:
   * compile `hula.p4`, and
   * start a Mininet instance with three ToR switches (`s1`, `s2`, `s3`)
     and two spine switches ( `s11`, `s22`).
   * The hosts (`h1`, `h2`, `h3`) are assigned IPs of `10.0.1.1`,
     `10.0.2.2`, and `10.0.3.3`.

2. You should now see a Mininet command prompt. Just ping `h2` from `h1`:
   ```bash
   mininet> h1 ping h2
   ```
Initially, the ping probe will not go through, as no path is set.

3. Type `exit` to close the Mininet command line.

The message was not received because each switch is programmed with
`hula.p4`, which drops all data packets. Your job is to extend this
file.

### A note about the control plane

P4 programs define a packet-processing pipeline, but the rules
governing packet processing are inserted into the pipeline by the
control plane.  When a rule matches a packet, its action is invoked
with parameters supplied by the control plane as part of the rule.

In this exercise, the control plane logic has already been
implemented.  As part of bringing up the Mininet instance, the
`run.sh` script will install packet-processing rules in the tables of
each switch.  These are defined in the `sX-commands.txt` files, where
`X` corresponds to the switch number.

**Important:** A P4 program also defines the interface between the
switch pipeline and control plane.  The `sX-commands.txt` files
contain lists of commands for the BMv2 switch API. These commands
refer to specific tables, keys, and actions by name, and any changes
in the P4 program that add or rename tables, keys, or actions will
need to be reflected in these command files.

## Step 2: Implement HULA

The `hula.p4` file contains a skeleton P4 program with key pieces of
logic replaced by `TODO` comments. These should guide your
implementation---replace each `TODO` with logic implementing the
missing piece.

A complete `hula.p4` will contain the following components:

1. Header type definitions for Ethernet (`ethernet_t`), HULA (`hula_t`),
   Source Routing (`srcRoute_t`), IPv4 (`ipv4_t`), UDP(`udp_t`).
2. Parsers for the above headers.
3. Registers:
  - `srcindex_qdepth_reg`: At destination ToR saves queue length of
     the best path from each Source ToR     
  - `srcindex_digest_reg`: At destination ToR saves the digest of the
     best path from each Source ToR    
  - `dstindex_nhop_reg`: At each hop, saves the next hop to reach each
    destination ToR
  - `flow_port_reg`: At each hop saves the next hop for each flow
4. `hula_fwd table`: looks at destination IP of HULA packets. If it is
   the destination ToR, it runs `hula_dst` action to set `meta.index`
   field based on source IP (source ToR).  The index is used later to
   find queue depth and digest of current best path from that source
   ToR.  Otherwise, this table just runs `srcRoute_nhop` to perform
   source routing.
5. `hula_bwd` table: at revere path, updates next hop to the
   destination ToR using `hula_set_nhop` action. The action updates
   `dstindex_nhop_reg` register.
6. `hula_src` table just checks the source IP address of a HULA packet
   in reverse path.  if this switch is the source, this is the end of
   reverse path, thus drop the packet.  Otherwise use `srcRoute_nhop`
   action to continue source routing in the reverse path.   
7. `hula_nhop` table for data packets, reads destination IP/24 to get
   an index.  It uses the index to read `dstindex_nhop_reg` register
   and get best next hop to the destination ToR.
8. The dmac table just updates ethernet destination address based on
   next hop.
9. An apply block that has the following logic:
  * If the packet has HULA header
    * On the forward path (`hdr.hula.dir==0`):
      * Apply `hula_fwd` table to check if it is the destination ToR or not
      * If this switch is the destination ToR (`hula_dst` action ran and 
      set the `meta.index` based on the source IP address):
        * read `srcindex_qdepth_reg` for the queue length of
          the current best path from the source ToR
        * If the new queue length is better, update the entry in
	  `srcindex_qdepth_reg` and save the path digest in
	  `srcindex_digest_reg`. Then return the HULA packet to the source ToR
          by sending to its ingress port and setting `hula.dir=1` (reverse path)
      * else, if this HULA packet came through current best path (`hula.digest`
        is equal to the value in `srcindex_digest_reg`), update its queue
	length in `srcindex_qdepth_reg`. In this case we don't need to send
	the HULA packet back, thus drop the packet.
    * On the reverse path (`hdr.hula.dir==1`):
      * apply `hula_bwd` to update the HULA next hop to the destination ToR
      * apply `hula_src` table to drop the packet if it is the source ToR of
        the HULA packet
  * If it is a data packet
    * Compute the hash of flow
    * **TODO** read nexthop port from `flow_port_reg` into a temporary variable,
      say `port`. 
    * **TODO** If no entry found (`port==0`), read next hop by applying
      `hula_nhop` table.
     Then save the value into `flow_port_reg` for later packets.
    * **TODO** if it is found, save `port` into `standard_metadata.egress_spec`
      to finish routing.
    * apply `dmac` table to update `ethernet.dstAddr`. This is necessary for
      the links that send packets to hosts. Otherwise their NIC will drop
      packets.
  * Update the TTL field
5. **TODO:** An egress control that:
   * For HULA packets that are in forward path (`hdr.hula.dir==0`)
   * Compare `standard_metadata.deq_qdepth` to `hdr.hula.qdepth` 
     in order to save the maximum in `hdr.hula.qdepth`
7. A deparser that selects the order in which fields inserted into the outgoing
   packet.
8. A `package` instantiation supplied with the parser, control, checksum
   verification and recomputation  and deparser.

## Step 3: Run your solution

1. Run Mininet same as Step 1
2. From the Mininet command line run
```bash
s1 ./send.py
```
to send HULA packets from all ToR switches (`s1`, `s2` and `s3`) to each other
on all paths.
3. run `h1 ping h2`. The ping should work if you have completed the
ingress control block
 
Now we are going to test a more complex scenario.  We send two iperf
traffic to `h3` from `h1` and `h2` But without sending HULA packets,
they will both use the same spine switch and as spine links have only
1mbps, they must share bandwidth, thus each can reach only 512kbps.
We test if with HULA, both iperf can reach 1mbps.

1. open a terminal window on `h1`, `h2` and `h3`:
```bash
xterm h1 h2 h3
```
2. start iperf server at `h3`
```bash
iperf -s -u
```
3. run iperf client in `h1`
```bash
iperf -c 10.0.3.3 -t 30 -u -b 2m
```
4. run iperf client in `h2`
```bash
iperf -c 10.0.3.3 -t 30 -u -b 2m
```
Wait for them to finish. Look at the window in `h3`.  Although there
are two paths to `h3`, both `h1` and `h2` use the same path and
aggregate bandwidth <= 1mbps

Now lets redo the test, but before step 4 we will run `send.py` twice.
1. open a terminal window on `h1`, `h2` and `h3`. If you have closed mininet,
you need to run `send.py` first, to setup initial routes:
```bash
xterm h1 h2 h3
```
2. start iperf server at `h3`
```bash
iperf -s -u
```
3. run iperf client in `h1`
```bash
iperf -c 10.0.3.3 -t 30 -u -b 2m
```
4. in mininet command window run
```bash
./send.py
```
This should let `s3` to know that the current chosen path has large
queue length.  But because of the path is congested, it will reach
after updates from other paths.  Let's send HULA packets again so that
the better path can replace current path.
```bash
./send.py
```
Alternatively, you can force `send.py` to run every five seconds by
passing `5` as an argument.

5. run iperf client in `h2`
```bash
iperf -c 10.0.3.3 -t 30 -u -b 2m
```
Both iperf should reach 1mbps now.

### Food for thought
* how can we implement flowlet routing say based on the timestamp of packets
* in the ingress control logic, the destination ToR always sends a HULA packet 
back on the reverse path if the queue length is better. But this is not necessary
if it came from the best path. Can you improve the code?

### Troubleshooting

There are several ways that problems might manifest:

1. `hula.p4` fails to compile.  In this case, `run.sh` will report the
error emitted from the compiler and stop.

2. `hula.p4` compiles but does not support the control plane rules in
the `sX-commands.txt` files that `run.sh` tries to install using the
BMv2 CLI.  In this case, `run.sh` will report these errors to
`stderr`.  Use these error messages to fix your `hula.p4`
implementation.

3. `hula.p4` compiles, and the control plane rules are installed, but
the switch does not process packets in the desired way.  The
`build/logs/<switch-name>.log` files contain trace messages describing
how each switch processes each packet.  The output is detailed and can
help pinpoint logic errors in your implementation.  The
`build/<switch-name>-<interface-name>.pcap` also contains the pcap of
packets on each interface. Use `tcpdump -r <filename> -xxx` to print
the hexdump of the packets.

#### Cleaning up Mininet

In the latter two cases above, `run.sh` may leave a Mininet instance
running in the background. Use the following command to clean up these
instances:

```bash
mn -c
```

## Next Steps

Congratulations, your implementation works and you have completed the
P4 tutorial
