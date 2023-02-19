---
title: "The story of rustables (so far)"
date: 2023-03-20T00:50:43+01:00
draft: false
---

> One netlink message a day, keeps the packets always  

## The context

Back in late 2021, I started to work on a minimal [QEMU](https://www.qemu.org/) wrapper to execute [Capture The Flag](https://en.wikipedia.org/wiki/Capture_the_flag#Computer_security) (CTF) challenges for the [THCon](https://thcon.party/) security conference.

We supplied a list of [recommendations](https://22.thcon.party/ctf_design/) for challenge designers, asking them to give us a Dockerfile and the sources necessary to reproduce and distribute the challenges.

The idea was that we would host the container images and expose them to the contestants, who would then attack the challenges hosted inside, win points, be happy, and come back the following year.

Some would probably suggest using Kubernetes, Swarm, Nomad, or any other container orchestrator.
But I am somewhat old school when it comes to technology, and not very experienced with either of these solutions, thus completely clueless regarding the best practices to secure these beasts.

All in all, I was looking into a manager of some kind that would have good properties, meaning "fairly secure" (an user solving a challenge should not give them access to the infrastructure running other challenges), "decently simple" (I could easily explain how to use/manage the tool to members of the team), and compatible with OCI (the image format used by the whole "cloud" ecosystem to distribute container images).

Because I had enough spare time at the moment, I decided to write it myself, and called the project CIRCE, mostly out of reference to the enchantress renowned for her use of the black arts, as the code of the project was of a dubious quality... The idea was to have an orchestrator spawning the docker containers inside light virtual machines[^qemu_light], and exposing the challenges to the internet via NAT redirections.

To be perfectly honest, I didn't search long for alternatives, because it was an opportunity to code something and have fun at the same time!
Of course, experienced people know that this is a classic example of [NIH syndrome](https://en.wikipedia.org/wiki/Not_invented_here) and thus a great recipe for disaster, and this project was no exception.

I should further clarify that this wasn't in any way a work project, only a spare time occupation, and I would definitely not pursue such a project in a work context, where my employer have fairly reasonable expectations that I should deliver something viable at the end of the road, and preferably without spending a silly amount on time on it!

While we are still being honest, I must admit the project went completely sideways when:
* D-day was approaching fast and the project was still 100% experimental
* I realized at the last minute (quite literally) that the Microsoft Azure VMs we were using - as part of the Microsoft Nonprofit program[^azure_sponsorship] - didn't like spawning nested VMs with KVM. Whoops...[^whoops]


As time was running out, we threw away my utterly broken project and decided to spawn the docker containers as-is (with the `docker` command line tool), and manage them manually. Doing this led to an hour delay in the start of the CTF, and quite a bit of stress on our end - mostly expressing itself in the form of curses and frantic invocations of `docker run`. But the CTF then went fairly smoothly, so I guess the event could have ended up far worse than it did.

Outside of all the obvious "project management" failures here (no proper planning or distribution of tasks in the team, lack of integration tests and of a test run, time overrun, a workload inadequate with our `work/(team_size*available_time)` ratio, and so on) and the fact that *CIRCE* truned out *in fine* to be perfectly useless, there was one positive byproduct: I started looking at [nftnl-rs](https://github.com/mullvad/nftnl-rs).

### nftnl-rs

Behind this cryptic name lies a Rust abstraction of [libnftnl](https://www.netfilter.org/projects/libnftnl/index.html), a userland C library.
In a classic demonstration of the usual programmer wisdom, I surmise someone here though hard about giving the project a fitting name, reminded themselves that [naming is hard](https://martinfowler.com/bliki/TwoHardThings.html), and decided to go with something as obvious as it is hard to utter:
*libfntnl* probably stands for something like ***lib**rary providing **nft**ables* support over **n**et**l**ink*.

The authors of the rust bindings [*nftnl-rs*](https://github.com/mullvad/nftnl-rs) went with the original name, removed the 'lib' prefix that I believe to be quite rare when Rust libraries are concerned, and added the overused `-rs` suffix to indicate that this is a *Rust* library.
This yields something like ***nft**ables* support over **n**et**l**ink in **r**u**s**t*.
Quite a mouthful, but also fairly explicit, and super easy to grep/lookup on the internet (looking at you /e/OS!), so there is that.

But enough about naming, what does this library do concretely?

The library exposes "high level" functions and macros to create and manipulate nftables objects: tables, chains, rules, sets and expressions.
Let's take a brief look at what these objects emcompass and we'll come back to the API of the library.

## Nftables

### The theory

I won't write a whole primer on nftables (I'm far too bad at networking to do that anyway!), but I wanted to point out that there is plenty of good ressources out there, not least of them the [nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page). The [Arch wiki](https://wiki.archlinux.org/title/Nftables) would also be a good starting place if you wanted to learn nftables through practice.

In a few words:
- The kernel provides a packet filtering subsystem called netfilter.
- Iptables and nftables are two sets of interfaces that userpace can interact with in order to program netfilter, nftables being the new kid in town[^new_nftables], providing improved behavior when applying rules (atomic complex operations)/a cleaner syntax/an official C library to manipulate nftables objects (compared to the `iptables` program)/less code duplication in the kernel/probably other advantages I don't know about.
- Like any firewall, the user defines what network flows must be allowed/blocked/logged.
- To do so, they define a list of rules, called - understandably - a *ruleset*[^3]. That ruleset is structured: the rules are organised inside *tables* and *chains*:
  - A *rule* is a list of expressions that processes a packet and define an action if the packet matches the rule.
  - A *chain* is an ordered list of rules, along with special properties:
    * the default *policy* (what to do for packets that are not matched by any rule);
    * the *type* of chain (it mostly serves to differentiate the type of transformation done in the chain: packet filtering/NAT translation/mangling/...);
    * the *hook* of the chain (where should the kernel "insert" the chain). Inside the kernel, there is multiple reserved points where a packet can be filtered:
      - `prerouting` - when a packet enters the network subsystem (read: any packet we received)
      - `input` - when the system is the destination of a packet (e.g. the response to a query, a web query sent to a server running, locally, ...)
      - `forward` - when the system received a packet, but is not its recipient: the packet is meant to be transferred to another host (e.g. your local router transferring packets from your computer to the internet, or vice-versa)
      - `output` - when the system emitted a packet to another host (e.g. your browser sending a DNS query to resolve the domain name of your favorite search engine)
      - `postrouting` - when a packet leaves the network susbsystem (read: any packet we sent).

      The *hook* determine which of those reserved points the chain will be attached to.  
      I feel compelled to note that if you prefer complex schemas to these hand-waving explanations, Wikipedia have [one](https://en.wikipedia.org/wiki/Netfilter#/media/File:Netfilter-packet-flow.svg) for you.
    * the *priority* of the chain (it sets the order of packet processing between different chains of the same *type*, i.e. what chain will be executed first).
  - A *table* is the outmost object, it contains multiple chains. Its only special property is the *family* of packets the chains it contains process (`ip` for IPv4, `ip6` for IPv6, `inet` for IPv4 and IPv6, and many others).

### In practice

Let's suspend our disbelief of the sentence "a picture is worth a thousand words" for a second, and take an example to demonstrate this in practice. To do that, let's enumerate the current ruleset on an hypothetical machine:
```bash
root@mymachine# nft list ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		iif "lo" accept
		ct state established,related accept
		ct state invalid drop
		tcp dport { 22, 443 } accept
		udp dport 53 accept
		counter reject with icmp port-unreachable
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state established,related accept
		ct state invalid drop
		iifname "virbr0" accept
		meta nfproto ipv4 counter reject with icmp port-unreachable
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}
```

Here, we have a single table, "filter", that can process IPv4 and IPv6 packets (because its family is `inet`).

That table contains three chains: `input`, `forward` and `output`.
Like I said earlier, `input` will process packets we received and were sent explicitly to us; `forward` will process packets we received but were targetting another system and `output` will process packets we emitted.  
We know that because of the `type filter hook forward priority filter;` lines that tell us readily all the special properties of the chains.

As a side note, I believe enyone that have ever used the `ipables` utility will side with me in saying that a readable format like that is a **huge** improvement.

#### What happens when we receive a packet?

All these chains will accept the packets if no rule matches (because the policy of all these chains is set to `accept`): that's the `policy accept;` lines.

Then, we have the rules themselves: `iif "lo" accept`, `counter reject with icmp port-unreachable`, ...

Each rule is a list of expressions (along with some metadata that we can blissfuly ignore). For example, `iif "lo" accept` is the concatenation of two parts (`iif "lo"` and `accept`) translating into three expressions:
- Loading the index of the network interface on which we received the packet
- Compare the content of that register with the interface index of the `lo` network interface[^4]
- Accept the packet

nftables relies on a small interpeter to evaluate sequentially the expressions of each rule: the expression `n` can only be executed if expressions `1`..`n-1` were all executed successfully before.  
In the `iif "lo" accept` example, the `accept` expression will only be executed if the index of the network interface of the packet matches the index of `lo`. Or to rephrase it, the packet will only be accepted if we received the packet on the proper interface, which is quite reassuring.

#### One subsystem to evaluate them all

As the astute reader may have figured out, in practice this works because the rules are executed on a small virtual machine - though not in the QEMU/KVM/Hyper-V/VMWare sense, but in the JVM/eBPF/webassembly/.NET sense: an hardware abstraction that allow building portable programs without knowing too much details about the underlying software.

That virtual machine (VM) have multiple registers that store and process information on a packet being evaluated.  
The value of these registers is not persistent across multiple rules: the only purpose of these registers is to share informations from an expression to the followings. For example, we saw above that `iif "lo"` was split in two expressions: loading the index of the network interface, and comparing that to the index of the `lo` interface. The result of that first expression is stored in a register, and the second expression loads from that register to perform the comparison.

When you create nftables `chains`, the kernel add that chain to the list of hooks to evaluate when a packet "hit" the hook point.

From that point on, any packet entering that hook point may eventually call into your nftables chain ("may" instead of "will" because there might be other hooks that take a decision to accept or drop the packet before you even sees it).

So by writing firewall rules, we are programming a virtual machine executing in kernel space to perform (nearly) arbitrary processing of the packet headers, we point the kernel to some part of the networking subsystem, and we ask it to kindly execute our virtual machine on all packets going through that point (technically, that *hook*).

As you can imagine, there are limits: we cannot select arbitrary points, there is no Just-In-Time engine, data persistence is very limited, but still: programming a firewall by writing bytecode for a virtual machine running in kernel-space, how cool is that?

##### How does it look like inside the kernel?

Here is an example where hooks are called inside the kernel. It is taken from `net/ipv4/ip_input.c`[^5]:

```c {linenos=table,hl_lines=["8-10"],linenostart=239}
/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ip_local_deliver(struct sk_buff *skb)
{
	[...]

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```

The details are not important here (and that's just as well, because I would be lying if I told you I understand well how netfilter works), but the idea is that whenever `ip_local_deliver` is called, the hooks registered for the target `(inet|ipv4) input` will be executed, in the order determined by their priorities.

Through some macros that we won't look at, the function `nf_hook` (in `include/linux/netfilter.h`) is called:

```c {linenos=table,hl_lines=[10,21],linenostart=211}
static inline int nf_hook([...])
{
	struct nf_hook_entries *hook_head = NULL;
	int ret = 1;

	[...]

	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
		break;
	[...]
	}

	if (hook_head) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, pf, indev, outdev,
				   sk, net, okfn);

		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();

	return ret;
}
```

Which in turns invoke the `nf_hook_slow` function (in `net/netfilter/core.c`):

```c {linenos=table,hl_lines=[6],linenostart=607}
int nf_hook_slow([...])
{
	unsigned int verdict;

	for (; s < e->num_hook_entries; s++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			break;
		[...]
		}
	}

	return 1;
}
```

We see that it iterates over every hook entry, executing them, and according to the resut, take a decision on the packet (not included in the code snippet above).

Through somewhat convolved (for kernel neophytes like me) code paths, the hook evaluation will call the function `nft_do_chain` (in `net/netfilter/nf_tables_core.c`):

```c {linenos=table,hl_lines=[12,15],linenostart=227}
unsigned int
nft_do_chain(struct nft_pktinfo *pkt, void *priv)
{
	[...]

	// this is actaully slightly more complicated, but we don't need to care here
	blob = rcu_dereference(chain->blob);
	rule = (struct nft_rule_dp *)blob->data;
	last_rule = (void *)blob->data + blob->size;

	regs.verdict.code = NFT_CONTINUE;
	for (; rule < last_rule; rule = nft_rule_next(rule)) {
		nft_rule_dp_for_each_expr(expr, last, rule) {
			[...]
			expr_call_ops_eval(expr, &regs, pkt);

			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		switch (regs.verdict.code) {
		[...]
		case NFT_CONTINUE:
			continue;
		}
		break;
	}

	switch (regs.verdict.code & NF_VERDICT_MASK) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NF_STOLEN:
		return regs.verdict.code;
	}

	[...]
}
```

As you could expect, each rule is executed one after the other (line 238), until a decision is taken (a `verdict` in nftables parlance).  
The same happens for each expression inside a rule (line 239).

The magic (the nftables virtual machine) is now just in reach: the `eval` method of each expression is called. For example, if the expression is `log` (which emits log messages with details about the packet), `nft_log_eval` is called, and does what we expect:

```c {linenos=table,linenostart=104,hl_lines=["10-12"]}
static void nft_log_eval(const struct nft_expr *expr,
			 struct nft_regs *regs,
			 const struct nft_pktinfo *pkt)
{
	const struct nft_log *priv = nft_expr_priv(expr);

	[...]
	}

	nf_log_packet(nft_net(pkt), nft_pf(pkt), nft_hook(pkt), pkt->skb,
		      nft_in(pkt), nft_out(pkt), &priv->loginfo, "%s",
		      priv->prefix);
}
```

To recap: once a kernel hook point is hit (because we received a packet that have a good "look"), the kernel will evaluate all chains registered for that hook, in order of their priority, and that involves evaluating every expression in every rule of these chains until a verdict is taken (mainly accepting/rejecting the packets, but there are others).

But enough copy-pasta of kernel code, let's go back to `nftnl-rs`.

## The API of nftnl-rs

I said earlier that nftnl-rs aims to provide high-level abstractions for manipulating nftables objects.

To see how that translates in code, here is an excerpt from [an official example](https://raw.githubusercontent.com/mullvad/nftnl-rs/6fdac471d8fae2be8c21f526fd3478bebc08e46f/nftnl/examples/add-rules.rs):

```rust {linenos=table}
const TABLE_NAME: &str = "example-table";
const IN_CHAIN_NAME: &str = "chain-for-incoming-packets";

fn main() -> Result<(), Error> {
    let mut batch = Batch::new();

    // equivalent to 'nft add table inet example-table'
    let table = Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Add);

    // equivalent to 'nft add chain inet example-table chain-for-incoming-packets { type filter hook input priority 0; }'
    let mut in_chain = Chain::new(&CString::new(IN_CHAIN_NAME).unwrap(), &table);
    in_chain.set_hook(nftnl::Hook::In, 0);
    in_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&in_chain, nftnl::MsgType::Add);

    // equivalent to 'nft add rule inet example-table chain-for-incoming-packets iif "lol" accept'
    let mut allow_loopback_in_rule = Rule::new(&in_chain);
    let lo_iface_index = iface_index("lo")?;
    allow_loopback_in_rule.add_expr(&nft_expr!(meta iif));
    allow_loopback_in_rule.add_expr(&nft_expr!(cmp == lo_iface_index));
    allow_loopback_in_rule.add_expr(&nft_expr!(verdict accept));
    batch.add(&allow_loopback_in_rule, nftnl::MsgType::Add);

    let finalized_batch = batch.finalize();
    send_and_process(&finalized_batch)?;
    Ok(())
}
```

We find again our *tables*, *chains*, *rules* and *expressions*.
The code is readable, even though it is somewhat quirky due to the use of [`CString`s](https://doc.rust-lang.org/alloc/ffi/struct.CString.html), but that's often an acceptable tradeoff to be able to reuse existing code (here, the C library `libnftnl`).

We are introduced here with a concept that appeared with nftables: *batches*.  
In order to provide atomic edition of arbitrarily complex policies, ruleset modifications are wrapped inside a *batch*. The kernel then guarantees that all the content of the batch will appear atomically (or that if there is an error because a rule or a message inside the batch is invalid, none of the batch is applied): there is not a single moment (no matter how tiny) where the batch is applied only in part.  
This brings great benefits: an invalid message in the batch **cannot** lead to an half-applied ruleset the whole batch will be rejected), and no messages can be filtered against a partially loaded ruleset.

We see its usage clearly in the code: 
1. We create a batch
1. We create objects and add them to the batch
1. We send the batch to the kernel
1. The kernel will apply it all at once (or none of it if we made an error)


libnftnl provides helpful functions to achieve all of this without learning too much of how objects must be formatted to please the kernel.  
To do that, it relies on its own representation of the various ntables objects, and only serialize/deserialize these objects to the kernel format when applying/reading rulesets.
As you can imagine, `nftnl-rs` cannot manipulate the internal representations of these objects directly, or it would be incredibly brittle (an update to `libnftnl` could break the ABI, which is not guaranteed by the library anyway).

To deal with this, `nftnl-rs` treats the `libftnl` objects as opaque C objects, and only manipulates them through the functions exposed by `libnftnl`. `nftnl-rs` thus acts as a wrapper allowing users to manipulate nftables objects without learning the lower-level `libftnl` API (the low-level details could still be manipulated manually, as they are exposed in the FFI crate[^crate] `nftnl-sys`, but you then have to be very sure to not break any API assumption, and you would then have to deal with the opaque C types yourselv) or resorting to unsafe rust.

## How did I use `nftnl-rs`?

In late 2021, I was in need of a rust library for manipulating nftables ruleset, and so I started using that library to build the container manager described in the introduction, before I lost myself trying to explain nftable. In practice, I was using a crudely patched version of `nftnl-rs` to build DNAT port redirections to the virtual machines hosting the challenges.

```
                      |###############|      calls into nftnl-rs to register firewall rules
          ------------| CIRCE manager |-----------------------------------------------------.
         |            |###############|-----------.                                         |
         |                                        |                                         |
         | spawns                                 | spawns                                  |
         ∨                                        ∨                                         v
 |####################|                         |####################|              @@@@@@@@@@@@@@@@@@
 |       QEMU X       |                         |       QEMU Y       |             |     nftnl-rs     |
 |--------------------|                         |--------------------|              @@@@@@@@@@@@@@@@@@
 |  custom init +     |                         |  custom init +     |            @@@@@@@@@@@@@@@@@@@@@@@
 |  container image X |                         |  container image Y |           |   libnftnl + libmnl   |
 |  ---------------   |                         |   ---------------  |            @@@@@@@@@@@@@@@@@@@@@@@
 | | eth0 (Virtio) |  |                         |  | eth0 (Virtio) | |                      ||
 | | @ip 10.0.0.X  |  |                         |  | @ip 10.0.0.Y  | |                      || asks the kernel to
 |  ---------------   |                         |   ---------------  |                      || setup some firewall rules
 |        ∧           |                         |          ∧         |                      ||
 |########|###########|                         |##########|#########|                      \/
          |                                                |               v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v
..........|.................. THE KERNEL FRONTIER .........|...............| netlink (kernel<->user-space API) |...........
          |                                                |               v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v∧v
          .-----.                            .-------------.                                ||
               |                            |                                               || configures the
               ∨                            v                                               || nftables subsystem
        -----------------          -----------------                                        \/
      | TAP device tapX |        | TAP device tapY |                                  ~~~~~~~~~~~~     
       -----------------          -----------------                        .-------->|  Netfilter |<-----.
              ∧                     ∧                                      |          ~~~~~~~~~~~~       |
              |                     |                                      |   routes packets from/to    |
              ∨                     ∨                                      |   the internet with DNAT    ∨
             -------------------------                                     |                 --------------------------
            | Virtual Ethernet bridge |<-----------------------------------.                | Physical Ethernet Device |
            | @ip 10.0.0.1            |                                                     | @ip <public ip>          |
             -------------------------                                                       --------------------------
                                                                                                   ∧       |
................... THE CLOUD FRONTIER (aka. someone else's computer) .............................|.......|..............
        ____                                                                                       |       |
       /    \                                                                                      |       |
      | @  @ |       netcat <public ip> <challenge Y port> ("I want to talk to challenge Y")       |       |
      |   ^  | ------------------------------------------------------------------------------------.       |
       \  - /                                                                                              |
        |  |                          "Sure, here is the challenge you must solve"                         |
       /    \ <--------------------------------------------------------------------------------------------.
 -----------------
| Beep bop, I'm a |
| CTF contestant! |
 -----------------

Legend:

|##########|     @@@@@@@@@     v∧v∧v∧v    ---------------------      ~~~~~~~~~~~~~~~~~~
| Program  |    | Library |    | API |   | Network "interface" |    | kernel subsystem |
|##########|     @@@@@@@@@     v∧v∧v∧v    ---------------------      ~~~~~~~~~~~~~~~~~~

```

Please do not be jealous of my artistic abilities, I always was very gifted when it came to art, and ASCII is no exception /s

Aaaanyway, once we have agreed that "to each is own" and that maybe "some people shouldn't dare share their *cough* art *cough*", we can focus on two interesting things in that awful schema that I haven't talked about yet:
1. libmnl (right next to libnftnl in the schema): this a library that works in tandem with libnftnl. libftnl knows how to serialize/deserialize/pretty-print/manipulate nftables objects, and libmnl is tasked with taking the serialized objects, exchanging them with the kernel over a netlink socket, and receiving the kernel-provided answers for libftnl to consume. Basically, libmnl is a wrapper over the C socket API for easier (read: higher-level) communication.
1. netlink (below the C libraries): this protocol exists to allow userland to talk to some kernel subsystems. The idea is that programs can talk to the kernel over a special type of socket, as if they were talking to a remote host in TCP or UDP. Unbeknownst to you, your computer uses netlink frequently to configure your network interfaces, mostly through programs like iproute2 (think `ip link/address/route/...`). In our case, netlink is the only (that I know of) interface that we can use to configure nftables.

## netlink

### The theory

To use netlink, the kernel provides a special address family, `AF_NETLINK`, that program can use when calling the `socket(2)`[^socket2] function.

To quote from the `netlink(7)` manpage[^netlink7]:

```
netlink_socket = socket(AF_NETLINK, socket_type, netlink_family);

Netlink is used to transfer information between the kernel and user-space processes.
It consists of a standard sockets-based interface for user space processes and an internal kernel API for kernel modules.

Netlink is a datagram-oriented service. Both SOCK_RAW and SOCK_DGRAM are valid values for socket_type.
However, the netlink protocol does not distinguish between datagram and raw sockets.

netlink_family selects the kernel module or netlink group to communicate with.
The currently assigned netlink families are:

NETLINK_ROUTE
      Receives routing and link updates and may be used to modify the routing tables (both IPv4 and IPv6), IP addresses,
      link parameters, neighbor setups, queueing disciplines, traffic classes, and packet classifiers (see rtnetlink(7)).

[...]

NETLINK_SELINUX (since Linux 2.6.4)
      SELinux event notifications.

[...]

NETLINK_NETFILTER (since Linux 2.6.14)
      Netfilter subsystem.
```

This tells us how libnftnl and libmnl must send messsages to the kernel (by opening a netlink socket with the parameter `NETLINK_NETFILTER`, and sending control messages over that socket), and we the content of the messages (*batches* and *tables* and so on), but we do not yet know how these messages are formatted.  
We need to bridge that gap between our high-level understanding of what libnftnl manipulates (the opaque C objects we mentioned) and what the library send to the kernel (nftables objects serialized to the wire format expected by the kernel).

### The mandatory example

Let's call our friend `strace` to our rescue, and use it to introspect the behavior of the official `nft` utility (it uses libnftnl and libmnl internally)[^rewrap]:
```c
root@mymachine# strace -yvf -s 250 nft list ruleset
[many initialization lines (this is strace after all!)]
# Open the netlink socket
socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) = 3<socket:[175398]>
[...]

# Check that nftables is supported
sendto(3<socket:[175398]>,
	[
		{nlmsg_len=20, nlmsg_type=0xa10 /* NLMSG_??? */, nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0},
		"\x00\x00\x00\x00"
	],
	20,
	0,
	{sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000},
	12) = 20
recvmsg(3<socket:[175398]>, {
	msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{
		iov_base=[
			{nlmsg_len=44, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWGEN, nlmsg_flags=0, nlmsg_seq=0, nlmsg_pid=19490},
			{nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(3)},
			[
				[{nla_len=8, nla_type=0x1}, "\x00\x00\x00\x03"],
				[{nla_len=8, nla_type=0x2}, "\x00\x00\x4c\x22"],
				[{nla_len=8, nla_type=0x3}, "\x6e\x66\x74\x00"]
			]
		],
		iov_len=69631
	}],
	msg_iovlen=1,
	msg_controllen=0,
	msg_flags=0
}, 0) = 44

# List the tables currently enabled
sendto(3<socket:[175398]>,
	[
		{nlmsg_len=20, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_GETTABLE, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0},
		{nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
	],
	20,
	0,
	{sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000},
	12) = 20
recvmsg(3<socket:[175398]>, {
	msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{
		iov_base=[
			{nlmsg_len=60, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWTABLE, nlmsg_flags=NLM_F_MULTI, nlmsg_seq=0, nlmsg_pid=19490},
			{nfgen_family=AF_UNIX, version=NFNETLINK_V0, res_id=htons(3)},
			[
				[{nla_len=11, nla_type=0x1}, "\x66\x69\x6c\x74\x65\x72\x00"],
				[{nla_len=8, nla_type=0x2}, "\x00\x00\x00\x00"],
				[{nla_len=8, nla_type=0x3}, "\x00\x00\x00\x03"],
				[{nla_len=12, nla_type=0x4}, "\x00\x00\x00\x00\x00\x00\x00\x05"]
			]
		],
		iov_len=69631
	}], msg_iovlen=1, msg_controllen=0, msg_flags=0},
0) = 60

# List the chains, the sets, and the rules. Additionally, for every existing set, list its elements
[truncated for brevity]
```

I understand this look frightening at first, but fear not, we will get through this.

#### `sento` invocations

We understand what the `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` invocation above does: it creates a bidirectionnal communication channel with the kernel, using the netlink protocol, and targetting the `netfilter` netlink subsystem. The return value of the system call is a file descriptor (a number that is associated in the kernel with the underlying socket).

But what are these calls to `sendto`?

Let's invoke the `send(2)`[^send2] manpage to get the prototype of that function:
```c
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
      const struct sockaddr *dest_addr, socklen_t addrlen);
```

As its name implies, this system call send messages over a socket.
The caller indicates the data to transmit with a buffer and the length of data to send.
There can also be flags to influence the behavior of the transmission.  
Finally, the sender indicates the destination of the message.

If we take the call above that enumerates all the nftables tables present on the system and apply our newfound knowledge of `sendto()`, we get:
```c
sockfd=3
buf=[
	{nlmsg_len=20, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_GETTABLE, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0},
	{nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
]
len=20
flags=0
dest_addr={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}
addrlen=12
```

The socket used here is the one we `nft` had juste created, identified as the file descriptor 3.  
The adress clearly states that we want to talk to the kernel (let's juste ignore the meaning of `nl_pid` and `nl_groups`, it won't matter for this article).  
As there is only one kernel, there is no need to further describe the destination, so the address only restates that we are using netlink.  
There is not much to say about the socket, nor the buffer length either.  
As there is no flags, I don't think I can say much about them.

This leaves us with only one remaining part, which by chance happens to be the juicy one: the message content.

#### How are netlink messages structured?

All netlink messages have the same struture: a sequence of objects with a header and a payload.  
The header indicates the length of the object, its type, eventually some flags, and a sequence number.
The payload contain the data of the request, its format is subsystem-specific (we will look into the format for netfilter below).

If we follow on the previous example, this gives:
```c
header={nlmsg_len=20, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_GETTABLE, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0}
payload={nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
```

The header follows a simple pattern:
```rust
#[repr(C)]
pub struct nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}
```
(Do not be impressed by the naming conventions: `nl` stands for netlink, `msg` for message and `hdr` for header)

The header type `nlmsg_type` use is twofold: selecting the netlink subsystem that the message is being sent to (here, the nftables subsystem with `NFNL_SUBSYS_NFTABLES`) and the operation code (in our case, `NFT_MSG_GETTABLE` which requests the list of all tables).  
Now for the insignificant technical details: the subsystem is specified in the most significant byte, while the operation is stored in the least significant. Hence you can construct the type by ORing the subsystem shifted by an byte (that is, a 8 bit shift) with the operation. This is what gives us the `NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_GETTABLE` from above.

For nftables, the payload is itself composed of two parts:
1. A nftables header, specifying the netlink version that we want to use (I suppose this exists solely for forward-compatibility), the protocol family that the message applies to (or `AF_UNSPEC` if we wish to be "family-agnostic" - to target all families), and the resource id shows the current nftables generation (a number that is increased when the ruleset is modified, it's all internal details, we won't really need to care about it).
	```rust
	#[repr(C)]
	pub struct nfgenmsg {
	    pub nfgen_family: u8,
	    pub version: u8,
	    pub res_id: __be16,
	}
1. An optional list of attributes.  
This list of attributes can be used to specify which information is being searched when performing a query, to specify the properties of an object being created, or to return the properties of an existing object.  
The attributes are optional because sometimes there is no need for more parameters: the type is enough. In the `NFT_MSG_GETTABLE` above for example, there is no need for attributes, so there are none.

I am talking about attributes here, but I have not defined them yet. Let's mend that offense.

#### What's an attribute?

To explain attributes, let's select a more complex example now: the result of the `NFT_MSG_GETTABLE` call.  
If we extract that from the `strace` output above, we get the following payload:
```c
[
	[{nla_len=11, nla_type=0x1}, "\x66\x69\x6c\x74\x65\x72\x00"],
	[{nla_len=8, nla_type=0x2}, "\x00\x00\x00\x00"],
	[{nla_len=8, nla_type=0x3}, "\x00\x00\x00\x03"],
	[{nla_len=12, nla_type=0x4}, "\x00\x00\x00\x00\x00\x00\x00\x05"]
]
```

Here we have a list of 4 attributes. 

But first, it is time to talk about Type-Length-Value[^tlv] (TLV) encodings, because that's what these attributes are.  
The idea is very simple: we want to transport multiple consecutive attributes, so we need to be able to specify the type of each attribute.  
To help the recipient know what is part of each attribute, we also need to indicate its length.   
Finally, we want to share the attribute content itself, the attribute value.
Thus we need three parts: Type, length and Value. TLV is this very simple encoding where we just concatenate the three parts together.  
Want to store multiple attributes? Not a problem, just concatenate them!

```
attr1------->+---------->attr2----->+---------->attr3------>+---------->attr4---
 |          ∧            |          ∧            |          ∧            |
 ∨          |            ∨          |            ∨          |            ∨
 -------------------------------------------------------------------------------
 | Type | Length | Value | Type | Length | Value | Type | Length | Value | ...
 -------------------------------------------------------------------------------
  \                     / \                     / \                     /
       attribute 1             attribute 2              attribute 3
```

This have some nice advantages:
* This format is super easy to parse (here in pseudocode):
  1. Check if the packet holds enough space for a type+length header. If it doesn't, we have finished parsing the packet
		```python
		if buffer.len() < sizeof(nlattr):
			return
  1. Read the type and the length in the buffer
		```python
		type = get_type_from_integer(buffer[0..type_size].to_integer())
		attribute_length = buffer[type_size..header_size].to_integer()
  1. Check if the packet still contains at least enough space to hold the value. If it doesn't, the packet is malformed
		```python
		if buffer.len() < attribute_length:
			raise Error(InvalidPacket)
  1. Read the value according to its type
		```python
		raw_value = buffer[header_size..attribute_length]
		value = type.decode(raw_value)
  1. Remove the first `length` bytes of the buffer, effectively skipping the attribute we just parsed (note that the length includes the header size itself, and is not only the size of the value)
		```python
		# add the necessary padding between objects
		full_attribute_length = get_padding(attribute_length)
		buffer = buffer[full_attribute_length..]
  1. The buffer now holds the next attribute. Go to step 1 to parse this attribute
* Conversely, it is easy to generate
* It does not compress data, which is also good for performance here because we can do many operations without copying data left and right
* It is forward compatible: if a new attribute appear but your program doesn't know how to decode it, it won't have to crash. It can just skip it, and that's the whole beauty: we don't need to know the specifics of an attribute to known how many bytes to throw away.

All right, enough theory for now, back to our dear netlink.

In netlink, attributes are TLV-encoded (as you may have guessed, I wouldn't have made a free digression on TLV).  
Attributes are once-again encoded by concatenating a header with a payload (the attribute value). The header is called `nlattr` this time:
```rust
#[repr(C)]
pub struct nlattr {
    pub nla_len: u16,
    pub nla_type: u16,
}
```
(it shouldn't come as a surprise that the developers were thrifty with the characters when they named the fields, and so the `nla` prefix stands for `netlink attribute`. I am starting to believe it to be a recurring phenomenon with C developers, even though the language itself does not impose such limits)

If we take one of the attributes we had previously, it's all starting to make sense, right?  
`[{nla_len=11, nla_type=0x1}, "\x66\x69\x6c\x74\x65\x72\x00"]` is an attribute making 11 bytes.  
This includes the header, which is 4 bytes wide, so the value is 7 bytes long. Its type is `1`, which maps to the `NFTA_TABLE_NAME` attribute (we'll see later how I know that).  
Finaly, the payload is `\x66\x69\x6c\x74\x65\x72\x00`. By the way, that's ASCII for `filter\0`, which is the name of the only table I have on the system where I ran the strace. So it checks out!

#### Wrapping up on too many layers

You might be thinking «That's quite a few layers you have there, dear sir. Far from me the idea to denigrate your explanations, yet I wouldn't mind a small summary, if you will».  
Well, if that is the case, you just might be in luck...

```
<    nlmsghdr   > <   nfgenmmsg   > <     attribute 1     > <     attribute 2     > <     attribute 3     > 
------------------------------------------------------------------------------------------------------------
| netlink header | nftables header | Type | Length | Value | Type | Length | Value | Type | Length | Value |
------------------------------------------------------------------------------------------------------------
   |        |             |
request     |         protocol
  type   request      family
          flags
```

So, we have a netlink header, standard across every netlink subsystems. Then we have a nftables-specific header, and finally we have the attributes that contain all the interesting properties about the objects that interest us.  
That's about it.

The brilliant thing here is that the netlink header also store the size of the message, and so netlink messages are a form of TLV-encoding, just like the attributes. This means we can (and we do) concatenate multiple messages together inside a single packet, as we know how to seek to the next message (just add the padded length of the message to the position of the current message).

So finally, a packet will look like this:
```
-------------------------------------------------------------------------------------------------
| netlink header | nftables header | attribute* | netlink header | nftables header | attribute* | ...
-------------------------------------------------------------------------------------------------
\                                              / \                                             / 
                first message                                       second message
```

That's it, you know everything I do about netlink, except one: nesting!

#### netlink and nesting

As you can imagine, describing complex nftables expressions is no easy feat.  
Let's practice with a tought experiment: if you were building it from scratch, how would you express the list of expressions that an nftables rule may hold?

We could devise a simple scheme where there is an attribute type for each expression (there could be a `TYPE_LOG`, `TYPE_CMP`, `TYPE_COUNTER`, and so on) to distinguish each attribute. The content of each attribute could be formatted according to a structure definition (probably something published in the public kernel API headers) that is specific to the attribute type.

For example, this could yield the following, hypothetical definitions:
```c
enum nftables_attribute_types {
	TABLE_NAME,
	CHAIN_NAME,
	EXPRESSSION_LOG,
	EXPRESSSION_COUNTER,
	EXPRESSSION_VERDICT,
	...
}

struct expression_log {
	char log_prefix[64];
}

struct expression_counter {}

enum verdict_actions {
	VERDICT_ACCEPT,
	VERDICT_DROP,
	VERDICT_REJECT,
}

struct expression_verdict {
	enum verdict_action action;
}
```

We could then imagine the rule `nft add rule this_is_the_filter_table this_is_the_input_chain log prefix "toto" accept` being encoded as something like that (not calculating the field lengths because I'm lazy):
```c
netlink_header={nlmsg_len=XXX, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWTABLE, nlmsg_flags=NLM_F_CREATE|NLM_F_ACK, nlmsg_seq=0, nlmsg_pid=0}
nftables_message_herder={nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
payload=[
	{nla_len=XXX, nla_type=TABLE_NAME}"this_is_the_filter_table"
	{nla_len=XXX, nla_type=CHAIN_NAME}"this_is_the_input_chain"
	{nla_len=XXX, nla_type=EXPRESSSION_LOG}(struct expression_log {.log_prefix="toto"})
	{nla_len=XXX, nla_type=EXPRESSSION_VERDICT}(struct expression_verdict {.action = VERDICT_ACCEPT })
]
```

But then we would have a nice protocol (netlink) for exchanging data and have chosen to build *another* binary formatting on top of it (well, to be precise, it would be store inside attributes exchanged via netlink).  
That would be fairly redundant.

Besides, think about what would be needed for forward compatibility in that tought experiment: what if the kernel developers wanted to add new options to an existing expression (e.g. adding the possibility of counting the number of fragmented packets in the `counter` expression)?  
Would they develop a `struct expression_counter2`, `struct expression_counter3`, defining new corresponding values for the enum `nftables_attribute_types` (`EXPRESSSION_COUNTER2`, `EXPRESSSION_COUNTER3`, ...)?  
While completely feasible (ask Microsoft, the stewards of backward compatibility, they excel at things like this), that's not really the bright design I would expect for communicating with a network subsystem developped in the last decade.

That why I'm pleased the kernel developers made a far better choice: attributes can be nested.

Nesting means that some arguments contain other arguments: you can express nested data structures that way.

The fact that this is true for "some arguments" is important here: only some attributes have nesting.  
The netlink format distinguishes nested and non nested attributes in their types: the most significant byte of the `nla_type` field is properties about that field. One of these properties is whether the attribute is nested. If it is, the real type number is ORed with the value 0x8000. For example, if the imaginary `TABLE_NAME` type above was declared as 1, then a nested version of that attribute would have a field value for `nla_type` of 0x8001, while a non-nested version of that attribute would have a field `nla_type` of 0x0001). To know if a field have nesting, you only need to AND `nta_type` with 0x8000 and check if the result is non-zero.

In practice, it's both easier and harder: knowing which argument types are nested or not are part of the API contract between the programmer and the kernel developers (the same API contract that define the meaning of each attribute, really).  
While the standard does not preclude the existence of attributes that are valid both in nested and non-nested forme, I haven't seen any such attribute "in the wild" yet, and I doubt they exist, as it would unnecessary burden both the user and the kernel to manipulate "hybrid" attributes (hence, support both modes for a single type, while two types could be easily generated if that was needed).

In addition, you can encode lists of elements: concatenate multiple attributes that share the same type (that's not specific to nesting, it would work perfectly well without, but it's still easier to use when you can have a dedicated object that encapsulates all the elements in the list).  
This means you shouldn't see netlink as a dictionary (or hashmap, associative mapping, or any other name this concept have) from keys to values: you can store multiple consecutive (or not) attributes that have the exact same type (something dictionaries generally do not allow).

For example, this is the real format for the same rule:
```c
netlink_header={nlmsg_len=XXX, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWTABLE, nlmsg_flags=NLM_F_CREATE|NLM_F_ACK, nlmsg_seq=0, nlmsg_pid=0}
nftables_message_herder={nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
payload=[
	{nla_len=XXX, nla_type=NFTA_RULE_TABLE}"this_is_the_filter_table"
	{nla_len=XXX, nla_type=NFTA_RULE_CHAIN}"this_is_the_input_chain"
	{nla_len=XXX, nla_type=0x8000|NFTA_RULE_EXPRESSIONS}NESTED:
		- {nla_len=XXX, nla_type=0x8000|NFTA_LIST_ELEM}NESTED:
			- {nla_len=XXX, nla_type=NFTA_EXPR_NAME}"counter"
			- {nla_len=XXX, nla_type=0x8000|NFTA_EXPR_DATA}NESTED:
				// initialize the counter to 0 bytes received
				- {nla_len=XXX, nla_type=NFTA_COUNTER_BYTES}0
				// initialize the counter to 0 packets received
				- {nla_len=XXX, nla_type=NFTA_COUNTER_PACKETS}0
		- {nla_len=XXX, nla_type=0x8000|NFTA_LIST_ELEM}NESTED:
			- {nla_len=XXX, nla_type=NFTA_EXPR_NAME}"immediate"
			- {nla_len=XXX, nla_type=0x8000|NFTA_EXPR_DATA}NESTED:
				// initialize the destination register to be VERDICT
				- {nla_len=XXX, nla_type=NFTA_IMMEDIATE_DREG}NFT_REG_VERDICT
				// set the data to write to the register
				- {nla_len=XXX, nla_type=0x8000|NFTA_IMMEDIATE_DATA}NESTED:
					- {nla_len=XXX, nla_type=0x8000|NFTA_DATA_VERDICT}NESTED:
						// We accept the packet
						- {nla_len=XXX, nla_type=NFTA_VERDICT_CODE}NF_ACCEPT
]
```
Up to 5 levels: that's quite high as far as nesting goes. If that were code, many (most?) developers would rightfully start tearing their hair and leaning into excessive alcohol consumption[^alcohol]!

(side note: if you wondered where the `accept` disappeared in that example, well it didn't: we used the `immediate` expression to put our decision - accepting the packet - into the decision register `NFT_REG_VERDICT`)

I think that's it, you have all the necessary clues to understand what follows (if I didn't confuse you utterly, that is).

Now, back to the genealogy of the newborn!

## The genesis of `rustables`

In October 2021, a fellow citizen nicknamed `lafleurdeboum` sent me an email essentially stating that:
* `nftnl-rs` had not seen much activity in the last few months, and the opened PRs were taking a long time to be reviewed
* Thanks to the [network](https://github.com/mullvad/nftnl-rs/network) graph on Github, he had seen my work on a fork of the library
* He though maybe we could join forces?

My reply was probably in the lines of "I have no idea how to properly maintain a project, I don't even know if I will still be working on nftnl-rs in a couple months, but sure, let's try!".

We created a fork called `rustables`.

At first, we tackled what we felt were the current issues with the library, given here in a heap:
* [Wrapping](https://gitlab.com/rustwall/rustables/-/commit/4a85637d88b563227194b4bfeb0cea330e712f79) all rust objects (sets, rules, chains, ...) in [Arc](https://doc.rust-lang.org/std/sync/struct.Arc.html) (an atomic wrapper that reference count an object and management the lifecycle of that object - freeing it when its last "holder" is done with it)
* Adding some [querying interfaces](https://gitlab.com/rustwall/rustables/-/commit/a1bf37cb23db06825f04e3990707cc220cffdedc) to list tables, chains, and so on
* Exposing [more control](https://gitlab.com/rustwall/rustables/-/commit/4fb6a75c839334ad3893f5a493eb70109122d594) over the nlftnl API for advanced use cases (via the introduction of methods that allow manipulating raw pointers to libnftnl objects)
* Adding support for [log expressions](https://gitlab.com/rustwall/rustables/-/commit/e05c222bc081e25bdacbd3c7a2ea6c169b4d593a)
* Easier [submission](https://gitlab.com/rustwall/rustables/-/commit/aa1cc7089a70d134f2d71f84293628e05818b07f) of `Batch`es
* Switching the license from dual-licensed MIT+Apache 2 to GPLv3: [here](https://gitlab.com/rustwall/rustables/-/commit/1e9605ab0c6e2f2461e8ad08398ba18a230f56d6) and [there](https://gitlab.com/rustwall/rustables/-/commit/26bfea8ed713ab68f0ffe3945e94fee1d766c98e)  
  Yes, this is perfectly legal and permitted by the license! To be fair, I was very surprised to discover that, I didn't know it was possible until `lafleurdeboum` explained it.
* Introducing a [CI pipeline](https://gitlab.com/rustwall/rustables/-/commit/c694d5109171e51ce16f40a79b55b496002feb84)
* Replacing the rustables-sys with [code generated automatically](https://gitlab.com/rustwall/rustables/-/commit/1e33e3ab0790d977add329e9686b4b9e5570ba3c) with bindgen on the build machines from the kernel headers
* Adding [abstractions](https://gitlab.com/rustwall/rustables/-/commit/792ab25a91e3cc667b8e42ffc82cb77f5d99af44) for building rules
* [Fixes](https://gitlab.com/rustwall/rustables/-/commit/3e48e7efa516183d623f80d2e4e393cecc2acde9) for ARMv8 platforms
* Documentation updates
* And so on...

We also wrote together many tests for the library, checking that for rules/tables/chains and some expressions, the output of the library would match a fixed byte string that contain the encoded netlink expression.  
That may not seem like much, but that's because you don't know me enough to know how I hate writing tests. At the same time I greatly enjoy the regression coverage and confidence they provide when present. Let's be generous with myself and blame this on cognitive dissonance. I might even go so far as to say *it looks like* developers as a community often suffer from the same problem: we all love developer tools and we rely everyday on numerous fundamental projects, yet we tend to rarely work on them ([mandatory xkcd](https://xkcd.com/2347/)).

We even wrote a trivial but terrible netlink abstraction for our tests (terrible because it really love memory allocations) to replace the fixed bytes strings: see [here](https://gitlab.com/rustwall/rustables/-/blob/master/src/tests/mod.rs#L29-124) for the implementation and [this example](https://gitlab.com/rustwall/rustables/-/blob/9ff02d4e40113ae10b6244a8a3d94c6e0bad5427/tests/expr.rs#L39-83) where we check the content of a rule with an expression.

### The awakening

Once that work was done, the project went to slumber for a bit (circa 8 months), before I decided to stop procrastinating and tackle my main gripe with the library.  
Indeed, whilst the project was working fairly well, I was still frustated by the dependency on libftnl: as part of my failed experiment for a container orchestrator, I was running a custom init binary in the virtual machines. At some point, I wanted to perform nftables operations *inside* the VMs, but I couldn't without embedding ~~the whole world~~ too many libraries:
```
$ ldd /nix/store/1a4fhy0291sycwmabk5mvfzjcwr8rccl-libnftnl-1.2.4/lib/libnftnl.so.11
	linux-vdso.so.1 (0x00007ffcbbf7a000)
	libmnl.so.0 => /nix/store/r056wg88r4syxxw944hylmyaa2ydj7c0-libmnl-1.0.5/lib/libmnl.so.0 (0x00007f674060d000)
	libc.so.6 => /nix/store/76l4v99sk83ylfwkz8wmwrm4s8h73rhd-glibc-2.35-224/lib/libc.so.6 (0x00007f6740400000)
	/nix/store/76l4v99sk83ylfwkz8wmwrm4s8h73rhd-glibc-2.35-224/lib64/ld-linux-x86-64.so.2 (0x00007f6740649000)
```

The idea is simple: can we get rid of `libftnl` completely, and generate rust-only (ignoring the embedded libc) static binaries?

First, some words of reassurance: the objective for doing so do not originate in a "Rewrite It in Rust" frenzy that came to overwhelm me, but rather from that desired to have a fully static binary (and also from having enought free time to look into it).

Thus began my work on `rustables-0.8`. 

To achieve this goal, I first started by the easy part: removing the uses of `libmnl` in our codebase. This wouldn't really remove the dependency to libmnl, because as can be seen in the `ldd` output above, `libnftnl` itself depends on `libmnl`, but it's still a first step towards more "code sovereignty".

This didn't entail a lot of work: replacing the references to the `mnl` crate with calls to the `socket` methods of the absolutely fabulous [`nix`](https://github.com/nix-rust/nix) crate, and [implementing some basic parsing](https://gitlab.com/rustwall/rustables/-/blob/e918159bf7478652e9da41f4a873c6e46b3733ca/src/query.rs#L97-160) of nfnetlink messages.

At this point, we had more rust code than before (mind you, not necessarily more qualitative than the code being replaced), hence more maintenance work, but we didn't provide more functionality, and we didn't depend any less on C libraries - we were still linked dynamically to `libnftnl`, and thus `libmnl`. Not very impressive, right?  
But hey, as they say, "things will get worse before they get better".

Then came the meat of the work: getting rid of all the opaque handles over `libnftnl` objects.

### The writer

I started by... commenting all the code, with the idea that I would uncomment each component when it was implemented without libnftnl.

Then a wrapper around the buffer holding netlink messages was defined:
```rust
pub struct NfNetlinkWriter<'a> {
    buf: &'a mut Vec<u8>,
    // hold the position of the nlmsghdr and nfgenmsg structures for the object currently being
    // written
    headers: Option<(usize, usize)>,
}

impl<'a> NfNetlinkWriter<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> NfNetlinkWriter<'a> {
        NfNetlinkWriter { buf, headers: None }
    }

    pub fn add_data_zeroed<'b>(&'b mut self, size: usize) -> &'b mut [u8] {
        let padded_size = pad_netlink_object_with_variable_size(size);
        let start = self.buf.len();
        self.buf.resize(start + padded_size, 0);

        // if we are *inside* an object begin written, extend the netlink object size
        if let Some((msghdr_idx, _nfgenmsg_idx)) = self.headers {
            let mut hdr: &mut nlmsghdr = unsafe {
                std::mem::transmute(self.buf[msghdr_idx..].as_mut_ptr() as *mut nlmsghdr)
            };
            hdr.nlmsg_len += padded_size as u32;
        }

        &mut self.buf[start..start + size]
    }

    pub fn write_header(&mut self, <hidden>) {
        // take care of padding
        let nlmsghdr_len = pad_netlink_object::<nlmsghdr>();
        let nfgenmsg_len = pad_netlink_object::<nfgenmsg>();

        // write the nlmsghdr and nfgenmsg
        <hiden>

        self.headers = Some((
            self.buf.len() - (nlmsghdr_len + nfgenmsg_len),
            self.buf.len() - nfgenmsg_len,
        ));
    }

    pub fn finalize_writing_object(&mut self) {
        self.headers = None;
    }
}
```

While not very elegant (especially the bit about the position of the headers in the buffer), it exposes functions useful for serializing objects: writing a header, obtaining a mutable buffer where the attributes of an object can be written, and finishing writting an object (which is as simple as forgetting the current header, thanks to netlink TLV nature).

In practice, the buffer `buf` is held by `Batch`es:
```rust
/// A batch of netfilter messages to be performed in one atomic operation.
pub struct Batch {
    buf: Box<Vec<u8>>,
    // the 'static lifetime here is a cheat, as the writer can only be used as long
    // as `self.buf` exists. This is why this member must never be exposed directly to
    // the rest of the crate (let alone publicly).
    writer: NfNetlinkWriter<'static>,
    seq: u32,
}
```

There is a bit of lifetime cheatery (which relies on unsafe code) here to hold two mutable pointers to the buffer. This is okay because we can either manipulate the buffer through the `writer`, or consume the `Batch` and return the buffer (thereby dropping the writer), so these two mutable references cannot be used *concurrently* to access the buffer.

The lifetime of a `Batch` is a follows:
```rust
// create a new Batch object that holds a buffer, and a NfNetlinkWriter that points to that buffer
let mut batch = Batch::new();

let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
// Add the nfnetlink representation of the table to the buffer *via* the NfNetlinkWriter methods:
// - write_header to write the header (duh, you might say)
// - add_data_zeroed to obtain a mutable reference to a buffer where the attributes of the table will be written
// - finalize_writing_object to signal to the writer that the object was entirely serialized
batch.add(&table, MsgType::Add);

// same thing with a chain
Chain::new(&table)
    .with_name(INBOUND_CHAIN_NAME)
    .with_hook(Hook::new(HookClass::In, 0))
    .with_policy(ChainPolicy::Drop)
    .add_to_batch(&mut batch);

// calls internally batch.finalize() that consumes the batch and return the buffer 'buf'
batch.send()?;
```

Along with the deserializing function defined when replacing libmnl, we have methods to abstract away the nlmsghdr/nfgenmsg parts, and we need "only" concern ourselves with expressing all nftables objects purely in rust, instead of manipulating handles to `libnftnl` opaque objects.  

However the task may look quite daunting: we saw how the messages are encoded, but implementing serialization and deserialization methods for all the possibles objects and expressions is not very attractive.
Besides, we know that there is a lot of similarities between these serializers/deserializers: they all implement the netlink format.  
Surely we do not need to write many implementations that share the same design, but differ only in their specifics (the name of the fields, and the corresponding netlink type)?  
But how would you express these similar patterns many times without repeating yourself too much?

The answer is as obvious as it is distateful: macros, of course!  
You know, these strings of cryptic symbols[^code_is_cryptic] assembled in a seemingly random order that in turn generate piles of (hopefully cleaner) code. The same macros that most programmers revere with a respect tinged with fear, knowing we are interacting with forces beyond our comprehension, waiting eagerly for a mistake to crush them under `syntax error`, or `expected token '(', got ';'`, or any other of these mystic errors that push people towards the cold embrace of insanity.

Well, all the dramatization aside, I still chose macros to help me achieve the de-libftnl-ization of `rustables`.

### Traits

First, `traits` (you know, the Rust version of a Java interface) were introduced, and the dreaded macros were actually written to implement these traits as automatically as I could envision.  
To be honest, what follows is the current iteration of the traits, as they evolved a bit over time but I didn't want to explain their whole history, so I settled on their current state.

#### `AttributeDecoder`

```rust
pub type NetlinkType = u16;

pub trait AttributeDecoder {
    fn decode_attribute(&mut self, attr_type: NetlinkType, buf: &[u8]) -> Result<(), DecodeError>;
}
```

The first trait, `AttributeDecoder`, is implemented by types that contains attributes - netlink objects that themselves contain attributes: like nftables objects (you know, tables, rules, and so on) and nested nfnetlink data structues.
The method `decode_attribute` is called by the parser while reading messages (replies really) from the kernel. It takes as argument the object currently being deserialized, the netlink type of an attribute that this object contains (e.g. `NFTA_TABLE_NAME`, `NFTA_TABLE_FLAGS`, and so on), and a reference to a buffer that holds the value for that attribute.

It will typically take the form of a `switch` (actually, the keywork for pattern matching is `match` in Rust), comparing the netlink type until it matches (or the attribute is unsupported), and calling upon the deserializer to decode the value from the buffer.

For the sake of the demonstration, let's suppose that we have a table with two attributes:
```
NFTA_TABLE_NAME="hi_there"
NFTA_TABLE_FLAGS=0xc0ffee
```
While deserializing this objects, the parser is going to act as follows:
1. Read the header: the header have the message type `NFT_MSG_NEWTABLE`: this is the description of a table.

    Create a new `Table` object with its [default](https://doc.rust-lang.org/std/default/trait.Default.html) implementation: all values are set to their default values. In practice, they will all default to `None` (wich means that the attribute is not present in the object), because all types are wrapped inside an [`Option`](https://doc.rust-lang.org/std/option/enum.Option.html) to be able to express cases where the attribute is not present.  
    In this example, we would basically have:
    ```rust
    let table = Table { name: None, flags: None };
    ```
1. Read the attributes in a loop:

    In pseudocode, this gives:
    ```rust
    let (attr_type, attr_buffer) = read_attribute(buffer)?;
    table.decode_attribute(attr_type, attr_buffer);
    ```
    1. The first attribute have a type of `NFTA_TABLE_NAME` and a length of 8 bytes (without the attribute header, 12 with it).
        ```rust
        // will be translated to assign the value "hi_there" to table.name
        table.decode_attribute(NFTA_TABLE_NAME, &buf[..8]);
        ```
    1. The second attribute will have a type of `NFTA_TABLE_FLAGS` and a length of 4 bytes.
        ```rust
        // will be translated to assign the value 0xc0ffee to table.flags
        table.decode_attribute(NFTA_TABLE_FLAGS, &buf[..4]);
        ```
1. We have finished consuming all the object (we read `nlmsg_len` bytes), the object is completely parsed.

At the end of the thought experiment, we have
```rust
table == Table { name: Some(String("hi_there")), flags: Some(0xc0ffee) }
```

And truth be told, the actual code for reading the attributes of an object is really not much more complicated than our explanation[^reworked_code]:
```rust
pub(crate) fn read_attributes<T: AttributeDecoder + Default>(buf: &[u8]) -> Result<T, DecodeError> {
    let mut remaining_size = buf.len();
    let mut pos = 0;
    let mut res = T::default();
    while remaining_size > pad_netlink_object::<nlattr>() {
        let nlattr = unsafe { *transmute::<*const u8, *const nlattr>(buf[pos..].as_ptr()) };
        // ignore the byteorder and nested attributes
        let nla_type = nlattr.nla_type & NLA_TYPE_MASK as u16;

        pos += pad_netlink_object::<nlattr>();
        let attr_remaining_size = nlattr.nla_len as usize - pad_netlink_object::<nlattr>();

        // the heart of the decoder: call the AttributeDecoder trait implementation for the object being parsed
        // (we use genericity to specify which 'decode_attribute' method to call)
        T::decode_attribute(&mut res, nla_type, &buf[pos..pos + attr_remaining_size])?;
        pos += pad_netlink_object_with_variable_size(attr_remaining_size);

        remaining_size -= pad_netlink_object_with_variable_size(nlattr.nla_len as usize);
    }

    Ok(res)
}
```

#### `NfNetlinkDeserializable`

```rust
pub trait NfNetlinkDeserializable: Sized {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError>;
}
```

Objects implementing `NfNetlinkDeserializable` are objects that can be deserialized as-is from a bytes buffer.  
This is true for the most basic objects, like a string or an integer attribute: once an attribute was found in the kernel message (say `NFTA_TABLE_FLAGS`), and the parser have verified inside the `decode_attribute` method that this attribute does exists for the object being deserialized (we will see how in a small moment), you must convert its content from a bytes buffer to a proper rust type (`u32` for the `NFTA_TABLE_FLAGS` example).  
But this is also true for complex strctures! Because in netlink objects are mostly self-contained, a complex object like an expression (it can be complex and possess many attributes, as we discussed earlier) also implements the `NfNetlinkDeserializable` trait.

The method `deserialize` will take as input what we hope[^hope_expectation] to be some structure or object in its serialized form, and it returns the deserialized attribute (a valide Rust type) and the remaining bytes that remains in the buffer once the attribute have been deserialized.  

For example, here is the implementation for deserializing a `String`. It consumes all its input, converts the string to UTF-8 (in Rust, `String`s are *required* to be valid UTF-8), and returns a nice, memory-safe, valid `String` object:
```rust
impl NfNetlinkDeserializable for String {
    fn deserialize(mut buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        // ignore the NULL byte terminator, if any
        if buf.len() > 0 && buf[buf.len() - 1] == 0 {
            buf = &buf[..buf.len() - 1];
        }
        Ok((String::from_utf8(buf.to_vec())?, &[]))
    }
}
```

In the previous example (`NFTA_TABLE_FLAGS`), we end up with `decode_attribute(NFTA_TABLE_FLAGS, [0xee, 0xff, 0xc0, 0x00])` (if you are on a little-endian architecture).  
The method `decode_attribute` the we looked at not a minute ago will in turn call the `NfNetlinkDeserializable` implementation of `u32`, resulting in a call to `u32::deserialize([0xee, 0xff, 0xc0, 0x00])`, and that call will evaluate to the deserialized attribute (`0xc0ffee`) and the remaining bytes that it didn't consume (here, an empty slice `[]`).

The most complex objects (because they include all the others) are the `Table`s, `Rule`s and other nftables objects. They all share the same implementation:
```rust
impl<T> NfNetlinkDeserializable for T
where
    T: NfNetlinkObject + AttributeDecoder + Default + Sized,
{
    fn deserialize(buf: &[u8]) -> Result<(T, &[u8]), DecodeError> {
        // parse_object is a method that takes a buffer, extract the
        // nlmsghdr/nfgenmsg headers out of it and calls the `read_attributes`
        // that we saw a moment ago
        let (mut obj, nfgenmsg, remaining_data) = parse_object::<T>(buf, ...)?;
        obj.set_family(ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?);

        Ok((obj, remaining_data))
    }
}
```

#### `NfNetlinkAttribute`

The two traits we covered so far, `AttributeDecoder` and `NfNetlinkDeserializable`, are needed to deserialize objects.  
But we want to be able to talk to the kernel, and not only to read its output, so deserialization is not enought.  
It's time for the serialization traits!

Thankfully, they are not very numerous: there is only one, `NfNetlinkAttribute` - which is quite badly called, when I think about it. I probably should have called it `NfNetlinkSerializable` for consistency...

```rust
pub trait NfNetlinkAttribute: Debug + Sized {
    // is it a nested argument that must be marked with a NLA_F_NESTED flag?
    fn is_nested(&self) -> bool {
        false
    }

    fn get_size(&self) -> usize {
        size_of::<Self>()
    }

    // example body: std::ptr::copy_nonoverlapping(self as *const Self as *const u8, addr.as_mut_ptr(), self.get_size());
    fn write_payload(&self, addr: &mut [u8]);
}
```

This trait is a bit more fleshed out that its deserialization counterparts, with its three methods:
- `is_nested` defines whether an attribute is nested (and thus the associated netlink type should hold the `0x8000` marker that indicates it is nested).
- `get_size` return the size the attribute will take when serialized.
- `write_payload` is the core of the serializer, it is the part that writes the C representation of the attribute to a buffer. The size of the buffer was determined previously with `get_size()`.

There is basically only two behaviors:
1. The attribute is a primitive type
    - `is_nested` return false
    - `get_size` return the size of the C representation of the primitive type (often the same size as the Rust reprensentation)
    - `write_payload` writes the C representation of the primitive type
1. The attribute is a complex structure
    - `is_nested` may or may not return true, depending on the kernel definition of that structure
    - `get_size` return the sum of the size of its components (calling `get_size()` for each of these components)
    - `write_payload` writes sequentially each attributes it contains (`struct nlattr` + the attribute content)

This is enought to be able to write any structure (no matter how deeply nested or complex it is) to a netlink buffer.

#### `NfNetlinkObject`

However, so far we talked about traits for serializing and deserializing nftables objects, structures and primitive types, but how do `rustables` users supposed to add or remove nftables top-level objects (Rules, Tables, ...)?

> If multiple pieces of code perform the same task, a function ye shall build.  
> If multiple pieces of code perform the same task, but with a slight twist, an argument is plenty.  
> If multiple pieces of code perform the same task, but with many twists, a trait it will be.

Well, let's pick yet another trait for that, then!

```rust
pub trait NfNetlinkObject:
    Sized + AttributeDecoder + NfNetlinkDeserializable + NfNetlinkAttribute
{
    const MSG_TYPE_ADD: u32;
    const MSG_TYPE_DEL: u32;

    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32) {
        let raw_msg_type = match msg_type {
            MsgType::Add => Self::MSG_TYPE_ADD,
            MsgType::Del => Self::MSG_TYPE_DEL,
        } as u16;
        writer.write_header(
            raw_msg_type,
            self.get_family(),
            (if let MsgType::Add = msg_type {
                self.get_add_flags()
            } else {
                self.get_del_flags()
            } | NLM_F_ACK) as u16,
            seq,
            None,
        );
        let buf = writer.add_data_zeroed(self.get_size());
        self.write_payload(buf);
        writer.finalize_writing_object();
    }

    fn get_family(&self) -> ProtocolFamily;

    fn set_family(&mut self, _family: ProtocolFamily) {
        // the default impl do nothing, because some types are family-agnostic
    }

    fn with_family(mut self, family: ProtocolFamily) -> Self {
        self.set_family(family);
        self
    }

    fn get_add_flags(&self) -> u32 {
        NLM_F_CREATE
    }

    fn get_del_flags(&self) -> u32 {
        0
    }
}
```

Yes, that's even messier than the previous traits, but our nftables objects are worth it, aren't they?

The `get_family`/`set_family`/`with_family` methods are a hack around the fact that when we perform queries, the objects header must contain the affected protocol family (ARP, IPv4, IPv6, ...). As the protocol family is not a netlink attribute, the kernel expects no attribute in the structures describing these objects, but that we still need to supply them nonetheless, hence we need to store them somewhere. So I decided to store them inside the Rust objects, but as a non-attribute (a field inside the structure that is not deserialized to and from nfnetlink messages). To manipulate that information when decoding/encoding the objects, we need some methods, and so the `*_family` methods are defined as trait methods so that the same code path can serialize all the different kinds of nftables objects.

The `get_add_flags`/`get_del_flags` returns flags to apply when requesting the creation or deletion of an object. They are useful for the same reason as the `*_family` methods: one code to ~~rule them all~~ serialize them all.

Only one method remains: `add_or_remove`. As its name indicates, this method is called to request the kernel to add or remove an nftables object. It does so by appending that request to a buffer (the buffer is held in a `NfNetlinkWriter`, to provide us with some neat abstractions over the buffer).  
All the other methods are details, but `add_or_remove` is the crux of the API: it is through this method that users can submit creation and demetion requests.

####  Traits recap

`AttributeDecoder` validates and deserializes attributes stored inside netlink structures.

`NfNetlinkDeserializable` implementations deserializes any type of object, from a primitive type to a complete nftables object.

`NfNetlinkAttribute` implementations exposes all the operations needed to serialize an object as if it were a netlink attribute.

Finally, `NfNetlinkObject` provides the API that users use to create and delete nftables objects.

Presented like that, it may not look so bad, but the existence of some many traits can also be seen as a serious wrench thrown in the path to enlightenment. Aehm, I meant: "the path to understanding the mess that is `rustables` design".

For those of us (like me) that have trouble juggling with many concept at once, let's take another example:

First, suppose we were to request a listing of every `Rule` present in some chain. We would submit our query, then we would iterate over the answer (`rustables` does this, but I won't expand on how it does that precisely, as it's not very interesting: it loops on the input, and extract each nlmsghdr object, processing them until the input buffer is empty).

Suppose that the kernel answer is a buffer that only holds a single rule, described in the netlink format below:
```c
netlink_header={nlmsg_len=XXX, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWTABLE, nlmsg_flags=NLM_F_CREATE|NLM_F_ACK, nlmsg_seq=0, nlmsg_pid=0}
nftables_message_herder={nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}
payload=[
	{nla_len=XXX, nla_type=NFTA_RULE_TABLE}"this_is_the_filter_table"
	{nla_len=XXX, nla_type=NFTA_RULE_CHAIN}"this_is_the_input_chain"
	{nla_len=XXX, nla_type=0x8000|NFTA_RULE_EXPRESSIONS}NESTED:
		- {nla_len=XXX, nla_type=0x8000|NFTA_LIST_ELEM}NESTED:
			- {nla_len=XXX, nla_type=NFTA_EXPR_NAME}"immediate"
			- {nla_len=XXX, nla_type=0x8000|NFTA_EXPR_DATA}NESTED:
				// initialize the destination register to be VERDICT
				- {nla_len=XXX, nla_type=NFTA_IMMEDIATE_DREG}NFT_REG_VERDICT
				// set the data to write to the register
				- {nla_len=XXX, nla_type=0x8000|NFTA_IMMEDIATE_DATA}NESTED:
					- {nla_len=XXX, nla_type=0x8000|NFTA_DATA_VERDICT}NESTED:
						// We accept the packet
						- {nla_len=XXX, nla_type=NFTA_VERDICT_CODE}NF_ACCEPT
]
```

How will this be deserialized?  
Inside the loop iterating over the netlink objects, `Rule::deserialize` is called on each object.  
Here there is only a single Rule, because every run will look mostly the same, so there is no point in doing the demonstration many time, but this would work exctly the same if there was a thousand rules instead.

So what will `Rule::deserialize(&buffer)` do?
1. Call `parse_object::<Rule>(&buffer)`. This will:
    1. Parse the netlink message header and nftables header.
    1. Call `read_attributes::<Rule>()` on the payload . This will:
        1. Create a default implementation of the rule: `let rule = Rule::default();`.
        1. Loop on the attributes inside the payload. Here, there are three, associated with the netlink types `NFTA_RULE_TABLE`, `NFTA_RULE_CHAIN` and `NFTA_RULE_EXPRESSIONS`. For each attribute, we call `Rule::decode_attribute(&mut rule, netlink_attribute_type, &netlink_attribute_value)`.
            1. Let's take a look at a simple one: `NFTA_RULE_TABLE`. This will result in a call equivalent to `Rule::decode_attribute(&mut rule, NFTA_RULE_TABLE, &"this_is_the_filter_table".as_bytes())`.
                 - Inside `Rule::decode_attribute`, `NFTA_RULE_TABLE` will be compared with every known attribute valid for a nftables Rule, and the attribute value will be deserialized as a String:
                    ```rust
                    let (name, _) = String::deserialize(buf)?;
                    rule.name = Some(name);
                    ```

                    This works because `String` implements the `NfNetlinkDeserializable` trait.
           1. The `decode_attribute` call will return, and we will iterate to the next attribute (`NFTA_RULE_CHAIN`), where the same process will happend again and will set the `rule.chain` field.
           1. For the sake of the argument, let's tackle the most complex attribute: the list of expressions. This will result in a call to `Rule::decode_attribute(&mut rule, NFTA_RULE_EXPRESSIONS, &buffer_that_contains_the_expressions)`. 

               Once again, `decode_attribute` will find the attribute type is acceptable (it is defined for a Rule)
                ```rust
                let (expressions, _) = ExpressionList<RawExpression>::deserialize(buf)?;
                rule.expressions = Some(expressions);
                ```

                This works because `ExpressionList<RawExpression>` implements the `NfNetlinkDeserializable` trait. It will in turn iterate over the attributes it holds (an `NFTA_LIST_ELEM` attribute), and call its deserializer (`RawExpression::deserialize`).  
                Now is the interesting part: `RawExpression` (the Rust representation for an nftables expression) also implements `AttributeDecoder`, because it takes multiple attributes.  
                So we see a common pattern here: primitive types (types that do not hold other types) implement `NfNetlinkDeserializable`, but complex structures must also implement `AttributeDecoder` for us to know how to decode he atributes they hold.

                - This rabbit hole goes deeper as we deserialize the attributes of the expression itself (recursively!) until the most nested attributes are deserialiazed, but I don't think iterating any further will bring anything to the discussion, except being as boring to write as it would be to read.

        1. Return the rule 
1. Update the protocol family of the generated Rule (`ruke.set_family(ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?`).
1. Return the deserialized rule.

Et voilà! A freshly deserialized rule.

The same sort of recurisve behavior happen when we serialize a Rust object to a netlink message, but with the `NfNetlinkAttribute` trait instead.

So, assuming we now have some understanding of the traits that compose the system, only one question remain: how to generate their implementation for all the nftables objects and structures that we want to support?

### Macros, macros everywhere

And that's where we bring some coherence back to this article: the macros[^article_initial_objective].

Because I'm conflicted about Rust [procedural macros](https://doc.rust-lang.org/reference/procedural-macros.html)[^opinion_procedural_macros], I first decided to use `macro_rules!` macros (the classical system of macros, that was present since the first release of `rustc`, unlike the procedural macros that appeared much later, in [rustc 1.30](https://blog.rust-lang.org/2018/10/25/Rust-1.30.0.html#procedural-macros).

The ideas is the following: we have structures that hold fields.  
The fields they are a netlink attribute, which means they all have:
- a netlink attribute type
- a name in the structure (to be manipulated)
- a type (to know how to serialiaze/deserialize the attribute value)

Time to get an example out of my pocket:

```rust
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Rule {
    id: Option<u32>,
    handle: Option<u64>,
    position: Option<u64>,
    table: Option<String>,
    chain: Option<String>,
    userdata: Option<Vec<u8>>,
    expressions: Option<ExpressionList>,
    family: ProtocolFamily,
}
```

If we ignore `family` that isn't a netlink attribute, we have a list of fields, with a name (`id`, `handle`, `position`, ...) and their types (`u32`, `String`, `ExpressionList`, ...), wrapped in an `Option` type for good measure (and maybe also because these attributes can be absent and we must be able to represent that fact).
But we still have to map the netlink attribute type to these fields.

In that first iteration, this was done with macros that took as argument the list of all the fields, and the netlink attribute type associated with each. Because of the limitations of classical macros, this required us to supply **a lot** of redundant information:
```rust
impl_attr_getters_and_setters!(
    Rule,
    [
        (get_table, set_table, with_table, sys::NFTA_RULE_TABLE, table, String),
        (get_chain, set_chain, with_chain, sys::NFTA_RULE_CHAIN, chain, String),
        (get_handle, set_handle, with_handle, sys::NFTA_RULE_HANDLE, handle, u64),
        (get_expressions, set_expressions, with_expressions, sys::NFTA_RULE_EXPRESSIONS, expressions, ExpressionList),
        (get_position, set_position, with_position, sys::NFTA_RULE_POSITION, position, u64),
        (
            get_userdata,
            set_userdata,
            with_userdata,
            sys::NFTA_RULE_USERDATA,
            userdata,
            Vec<u8>
        ),
        (get_id, set_id, with_id, sys::NFTA_RULE_ID, id, u32)
    ]
);

impl_nfnetlinkattribute!(inline : Rule, [
        (sys::NFTA_RULE_TABLE, table),
        (sys::NFTA_RULE_CHAIN, chain),
        (sys::NFTA_RULE_HANDLE, handle),
        (sys::NFTA_RULE_EXPRESSIONS, expressions),
        (sys::NFTA_RULE_POSITION, position),
        (sys::NFTA_RULE_USERDATA, userdata),
        (sys::NFTA_RULE_ID, id)
]);
```

The first macro ([`impl_attr_getters_and_setters!`](https://gitlab.com/rustwall/rustables/-/blob/66de507d2d33c03203b996a0d1797543e84c4b3d/src/parser.rs#L403-476)) generates getters and setters for the fields. They allow users of the library to easily manipulate the properties of the objects. The macros takes as input the getters/setters names (`get_xxx`, `set_xxx` and `with_xxx`), the netlink attribute type (`sys::NFTA_XXX`), the field name and the field type.  

My favorite setter is the chaining method `with_<field>` that uses the [Builder pattern](https://blog.logrocket.com/build-rust-api-builder-pattern/) to quickly create an object: e.g. `Rule::default().with_table("great_table").with_chain("the_chain").with_position(0)`.

The second macro ([`impl_nfnetlinkattribute`](https://gitlab.com/rustwall/rustables/-/blob/66de507d2d33c03203b996a0d1797543e84c4b3d/src/parser.rs#L523-597)) generates an implementation of the `NfNetlinkAttribute` trait (you know, the one that serializes objects). The basic idea is fairly simple[^reworked_code]: iterate over every field and write them by calling *their* `NfNetlinkAttribute` implementation.
```rust
macro_rules! impl_nfnetlinkattribute {
    ($struct:ident, [$(($attr_name:expr, $internal_name:ident)),+]) => {
        impl NfNetlinkAttribute for $struct {
            fn get_size(&self) -> usize {
                let mut size = 0;

                $(
                    if let Some(val) = &self.$internal_name {
                        // Attribute header + attribute value
                        size += pad_netlink_object::<nlattr>()
                            + pad_netlink_object_with_variable_size(val.get_size());
                    }
                )+

                size
            }

            unsafe fn inner_write_payload(&self, mut addr: *mut u8) {
                $(
                    if let Some(val) = &self.$internal_name {
                        unsafe {
                            $crate::parser::write_attribute($attr_name, val, addr);
                        }
                        let size = pad_netlink_object::<nlattr>()
                            + pad_netlink_object_with_variable_size(val.get_size());
                        addr = addr.offset(size as isize);
                    }
                )+
            }
        }
    };
}
```

I am glossing over scary details like the fact there is multiple ways to call the macro, depending on whether the object you want to generate is nested or not, which requires us to use recursive macros to share code between the various implementations. In truth, unlike the code sample above, `impl_nfnetlinkattribute!(inline : ...)` (non-nested objects) and `impl_nfnetlinkattribute!(nested : ...)` (nested objects) both calls `impl_nfnetlinkattribute!(__inner : ...)` which generates the code parts common to the two scenarii.

In fact, there was also a macro ([`create_wrapper_type!`](https://gitlab.com/rustwall/rustables/-/blob/66de507d2d33c03203b996a0d1797543e84c4b3d/src/parser.rs#L599-637)) that combined both macros, for the pleasure of masochistic developers.

These terrible aspects - hair-tearing recursivity, nausea-inducing readibility - of the macros frustrated me.  
Let's be real: the macros worked, but they were very much unmaintainable, non-extensible, exceedingly verbose. In a word: it was deeply *inelegant*.

### Procedural macros to the rescue

> "I suppose it is tempting, if the only tool you have is a hammer, to treat everything as if it were a nail."  
> *Abraham Maslow*

It was time to take a look inside the Rust toolbox and find a better tool, because doing increasingly complex operations with recursive macros was a pain.

When it comes to code generation, there is not an infinite number of solutions:
- declarative (classical) macros
- procedural macros
- an external code generation system (it is then *your* job to handle the integration with cargo)

I had originally excluded procedural macros because I felt they were too heavyweight - you need to create a different crate that will hold the macros[^procedural_design] -, and they add quite a few dependencies for building the package (to be easy to manipulate at least, [`syn`](https://docs.rs/syn/2.0.2/syn/) and [`quote`](https://docs.rs/quote/1.0.26/quote/) are really handy).

But as I did not want to bring in an external tool, or to write brittle shell scripts, it is with a heavy heart that I finally resolved myself to switch to procedural macros.  
Despite my opinions on them, honesty requires me to admit this was the best technical decision I ever made on the project.

Unlike the declarative macros, which copy/paste some elements (be it an identifier, a type path, or a primitive token) around - possibly recursively, which C macros cannot do, buy the way -, procedural macros are far mor powerful: they take as input the list of all the tokens, and they output a new set of tokens, which is then what's get compiled by `rustc`.  
This means we can craft arbitrary tokens out of the input, or even create new ones out of this air if we want to, though the use for such a thing is less obvious. This is basically preprocessing on steroids, allowing you to manipulate complex inputs, like bespoke [DSLs](https://en.wikipedia.org/wiki/Domain-specific_language), while offering extremely fine grained control of the output. Some people even wrote crates that [embed code written in another language directly inside Rust code](https://blog.m-ou.se/writing-python-inside-rust-1/).

After the switch, the result is **much** cleaner, yielding code far sleeker that what I had written previously. See for yourself:
```rust
#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct(derive_deserialize = false)]
pub struct Rule {
    family: ProtocolFamily,
    #[field(NFTA_RULE_TABLE)]
    table: String,
    #[field(NFTA_RULE_CHAIN)]
    chain: String,
    #[field(NFTA_RULE_HANDLE)]
    handle: u64,
    #[field(NFTA_RULE_EXPRESSIONS)]
    expressions: ExpressionList,
    #[field(NFTA_RULE_POSITION)]
    position: u64,
    #[field(NFTA_RULE_USERDATA)]
    userdata: Vec<u8>,
    #[field(NFTA_RULE_ID)]
    id: u32,
}

impl NfNetlinkObject for Rule {
    const MSG_TYPE_ADD: u32 = NFT_MSG_NEWRULE;
    const MSG_TYPE_DEL: u32 = NFT_MSG_DELRULE;

    fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    fn set_family(&mut self, family: ProtocolFamily) {
        self.family = family;
    }

    // append at the end of the chain, instead of the beginning
    fn get_add_flags(&self) -> u32 {
        NLM_F_CREATE | NLM_F_APPEND
    }
}
```

That's it! With that code, we generate getters/setters, the `NfNetlinkAttribute` and `AttributeDecoder` implementations. Everything we need to serialize/deserialize a Rule.  
Not only is this cleaner, this is also shorter: 36 lines instead of 81 lines previously, while providing exactly the same functionality.

So how does it work? Because I'm lazy[^laziness], I will not paraphrase the documentation I wrote a couple days ago, and I will satisfy myself with pasting it below:
```rust
/// `nfnetlink_struct` is a macro wrapping structures that describe nftables objects.
/// It allows serializing and deserializing these objects to the corresponding nfnetlink
/// attributes.
///
/// It automatically generates getter and setter functions for each netlink properties.
///
/// # Parameters
/// The macro have multiple parameters:
/// - `nested` (defaults to `false`): the structure is nested (in the netlink sense)
///   inside its parent structure. This is the case of most structures outside
///   of the main nftables objects (batches, sets, rules, chains and tables), which are
///   the outermost structures, and as such cannot be nested.
/// - `derive_decoder` (defaults to `true`): derive a [`rustables::nlmsg::AttributeDecoder`]
///   implementation for the structure
/// - `derive_deserialize` (defaults to `true`): derive a [`rustables::nlmsg::NfNetlinkDeserializable`]
///   implementation for the structure
///
/// # Example use
/// ```
/// #[nfnetlink_struct(derive_deserialize = false)]
/// #[derive(PartialEq, Eq, Default, Debug)]
/// pub struct Chain {
///     family: ProtocolFamily,
///     #[field(NFTA_CHAIN_TABLE)]
///     table: String,
///     #[field(NFTA_CHAIN_TYPE, name_in_functions = "type")]
///     chain_type: ChainType,
///     #[field(optional = true, crate::sys::NFTA_CHAIN_USERDATA)]
///     userdata: Vec<u8>,
///     ...
/// }
/// ```
///
/// # Type of fields
/// This contrived example show the two possible type of fields:
/// - A field that is not converted to a netlink attribute (`family`) because it is not
///   annotated in `#[field]` attribute.
///   When deserialized, this field will take the value it is given in the Default implementation
///   of the struct.
/// - A field that is annotated with the `#[field]` attribute.
///   That attribute takes parameters (there are none here), and the netlink attribute type.
///   When annotated with that attribute, the macro will generate `get_<name>`, `set_<name>` and
///   `with_<name>` methods to manipulate the attribute (e.g. `get_table`, `set_table` and
///   `with_table`).
///   It will also replace the field type (here `String`) with an Option (`Option<String>`)
///   so the struct may represent objects where that attribute is not set.
///
/// # `#[field]` parameters
/// The `#[field]` attribute can be parametrized through two options:
/// - `optional` (defaults to `false`): if the netlink attribute type (here `NFTA_CHAIN_USERDATA`)
///   does not exist, do not generate methods and ignore this attribute if encountered
///   while deserializing a nftables object.
///   This is useful for attributes added recently to the kernel, which may not be supported on
///   older kernels.
///   Support for an attribute is detected according to the existence of that attribute in the kernel
///   headers.
/// - `name_in_functions` (not defined by default): overwrite the `<name`> in the name of the methods
///   `get_<name>`, `set_<name>` and `with_<name>`.
///   Here, this means that even though the field is called `chain_type`, users can query it with
///   the method `get_type` instead of `get_chain_type`.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn nfnetlink_struct(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item).unwrap();
    let name = ast.ident;

    let args = match parse_struct_args(attrs) {
        Ok(x) => x,
        Err(_) => abort!(Span::call_site(), "Could not parse the macro arguments"),
    };

    let mut fields = /* iterate over the fields and extract the relevant ones */;

    // Generate an `AttributeDecoder` implementation for the structures.
    // This is done through iterating over every field, and comparing the netlink
    // type attribute value to the expected value for that field.
    // If the field matches, we try a deserialization, and return an error if this fails.
    let decoder = if args.derive_decoder {
        let match_entries = fields.iter().map(|field| {
            let field_name = field.name;
            let field_type = field.ty;
            let netlink_value = &field.netlink_type;
            quote!(
                x if x == #netlink_value => {
                    let (val, remaining) = <#field_type>::deserialize(buf)?;
                    if remaining.len() != 0 {
                        return Err(crate::error::DecodeError::InvalidDataSize);
                    }
                    self.#field_name = Some(val);
                    Ok(())
                }
            )
        });
        quote!(
            impl crate::nlmsg::AttributeDecoder for #name {
                fn decode_attribute(&mut self, attr_type: u16, buf: &[u8])
                    -> Result<(), crate::error::DecodeError>
                {
                    match attr_type {
                        #(#match_entries),*
                        _ => Err(crate::error::DecodeError::UnsupportedAttributeType(attr_type)),
                    }
                }
            }
        )
    } else {
        proc_macro2::TokenStream::new()
    };

    /* do the same for `NfNetlinkAttribute`, `NfNetlinkDeserializable` and the getters/setters */

    // generate a new structure, along with all the implementation we just generated
    quote! {
        #(#attrs) * #vis struct #name {
            #(#new_fields)*
            #(#identical_fields),*
        }

        #(#getters_and_setters) *

        #decoder

        #nfnetlinkattribute_impl

        #nfnetlinkdeserialize_impl
    }.into()
}
```

Quite a bit of machinery (notably to parse the arguments of the macros, which I've not included here for brevity) but infinitely more flexible: adding a new argument is no longer an obstacle course.  
So I can't say I'm unhappy about the change.

Thus concludes our tour of the recent changes to the core of `rustables`.

## Lessons learned along the way

Now, I know failing is part of the process to success, but we have to get some knowledge out of the failures. Here is what I gained:
- The usual "premature optimisation is the root of all evil" (Donald Knuth) lesson: the small build time gains from using procedural macros was completely outweighted by the abhorrent readability disadvantage of the fully self-contained (meaning: requiring not further build dependencies), declarative Rust macros.
- When the community is excited about a techology, they may be right: if everyone is using procedural macros, it might not be because they are attracted to the latest shiny thing, but because it solves a real issue for them. And if that is the case, maybe you have the same issue too.
- Documentation is crucial. While working on this endeavor, I had to lurk through the kernel code to understand what arguments were expected for some , because the kernel documentation on nfnetlink is not very large - that I know of. This was not a fabulous experience. In fairness, that this is a clear downside of `rustables` currently too, and I understand it may put off developers. We need to do better on that point.
- Tests, tests, tests[^ballmer]! They really really helped the process of rewriting the serializer while ensuring we get the same byte-for-byte result. As the saying goes, "testing proves the presence of bugs, not their absence". Yet having no tests means that you cannot detect regressions, and it is a sure way to lose time in the long term.

## Work remains

To sum the work quickly, libnftnl and libmnl were basically removed from the equation entirely. We are no longer linking against these libraries, we no longer manipulate libnftnl raw objects through the FFI layer, everything is now in Rust.
However we are still not where I would like to be on multiple points.

There is still a lot of work to do to reach a satisfying state:
- Binary size: examples/firewall.rs generates a 420 Kb binary when built statically against musl, with stripping and LTO enabled. That's too much!
- Documentation: very little documentation. Worse: I removed a fair bit of doc comments while I switched to macros, because I couldn't make them fit with code generation. It should possible to support them again now that we use procedural macros.
- Abstraction: logic errors are too easy to make. We should consider writing a higher level interface that ensures that the expressions are used correctly (we validate the type inside each expression, but we do not yet have a way to know if two consecutive expressions are manipulating the nftables register in a sane way - e.g. not comparing the name of an interface with an IP address).

If you have time to loose and want to contribute, don't be afraid, I will gladly accept contributions (and `lafleurdeboum` will probably be happy to have other contributors too)! The gitlab is [here](https://gitlab.com/rustwall/rustables).

That's all I wanted to shared today[^writing_time], and I hope this was an entertaining read.  
Till we meet again, fellow reader.


***

## Edit history

No modification so far


[^qemu_light]: QEMU+VirtIO really, so nothing actually light, except for the fact that the virtual machines would only execute a minimalistic userpace.

[^whoops]: It was actually half an hour before the start of the event, not a couple minutes, but still, I got to experiment with what testing in production must feel like, and my conclusion on the matter can be summarized as "3/10 wouldn't recommend".

[^new_nftables]: Well, "new" being 2014 here, but you know how software transitions can be long when they require a brutal switch (Python 2->3, IP v4->v6, etc.).

[^azure_sponsorship]: While I'm personally not a huge fan of Azure (or Microsoft offerings in general), I would like to thank them for offering generous quotas for non-profits, this is useful and greatly helped us for the CTF!

[^3]: Beware, the order of the rules matter, so it is definitely not a mathematical set!

[^4]: The index is taken as calculated when the rule was inserted in the kernel. This is the main difference between `iif` and `iifname`: `iif` computes that index once and stores that index in the rule (forgetting about the interface name entirely), while `iifname` checks the interface name against the value you provided for every packet.

[^5]: All code excerpts below are taken from commit `e1c04510f521e853019afeca2a5991a5ef8d6a5b` in the Linux kernel. I may have slightly rewritten some parts of that code to make it shorter for this posts. If you see an error, assume it is mine.

[^socket2]: https://www.man7.org/linux/man-pages/man2/socket.2.html

[^netlink7]: https://man7.org/linux/man-pages/man7/netlink.7.html

[^rewrap]: I allowed myself to rewrap the text to make it sligthly more readable.

[^crate]: A **crate** is the Rust word for a package (the language has a first-call package manager called `cargo`), whether it is a *library* or a *binary*. Here, it is used in the sense of *library*.

[^send2]: https://www.man7.org/linux/man-pages/man2/send.2.html

[^tlv]: https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value

[^alcohol]: Mind that I'm not encouraging you to drink alcohol, only to keep your code nesting from reaching "I would love for my eyes to stop bleeding" levels.

[^reworked_code]: Once again, the code is slighty reworked to remove uninteresting parts and keep this article "short".

[^code_is_cryptic]: Some might say that to an untrained eye, any computer code is cryptic. They may be right (which developer doesn't have a member of their family that have trouble doing anything computer-related that is more complex than reading their emails?), but that doesn't mean we should all program in [brainfuck](https://en.wikipedia.org/wiki/Brainfuck), or less sarcastically, in an assembly language. Code is meant to be mostly read, and sometimes rewritten, so it must remains readable (sorry, not sorry [APL](https://en.wikipedia.org/wiki/APL_(programming_language))).

[^opinion_procedural_macros]: While they can give really nice results (as we will see soon), the use of tokens as the "expressivity limit" (completely made up term, by the way) that can be manipulated is frustrating at time.: I don't mean you can manipulative higher-levels constructs made of multiple tokens (you obviously can manipulate them thanks to libraries like [syn](https://docs.rs/syn/latest/syn/). Rather, I mean that information not present in the tokens is not accessible at all: you cannnot check if a token exists in the current context or not, if two types are one and the same, etc. This is understandable because it would be hard to obtain high-level information with the current compiler design (or so I read somewhere), and it would make the compilation far more complex, but it still itches from time to time.

[^hope_expectation]: We can never be sure, so we have to expect failures everywhere. Good thing Rust forces us to account for them (to handle them or to `abort()`), then!

[^procedural_design]: From what I understand, procedural macros are built as shared libraries and loaded dynamically by the rustc compiler when building the crate that requires them. This requires separating the macros from the annotated crate.

[^article_initial_objective]: When I started writing this article, I actukllay wanted to talk mostly about the macros, but I got kinda lost in the process, and here we are.

[^laziness]: I am afraid this is not the first time since I began this article that a choice was made, and I *nearly always* did default to the lazy one

[^ballmer]: [https://www.youtube.com/watch?v=I14b-C67EXY](https://www.youtube.com/watch?v=I14b-C67EXY) (not a Rickroll, I promise)

[^writing_time]: Stricly speaking, I took an unreasonable amount of time writing the few words on this page, so "today" isn't very accurate, but for the sake of colloquialism, I'll let it pass.
