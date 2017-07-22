# [Liquid Investigations](https://github.com/liquidinvestigations): Node
Discovery Daemon

This repository implements a method finding out in real time what other Liquid
Investigations nodes are online.

Ths discovery service must be run as `root`.


## The basic principle

[Zeroconf](https://en.wikipedia.org/wiki/Zero-configuration_networking) is
being used for discovery of the other nodes in a network. Each node publishes
itself as a `_liquid._tcp.local` service using
[avahi-daemon](https://packages.debian.org/jessie/avahi-daemon).

Each node in the network must have a unique hostname by which it will be
identified. For the test, the hostnames used are `vagrant-box-two.liquid`,
`vagrant-box-two.liquid`, and `vagrant-box-three.liquid`. The hostnames can
have any domain, like `my-pretty-box.me` or `the-cool-box.org`. The hostnames
should consist only of smallcase letters and the hyphen ('-'). The hostnames
must have a domain to work.

Each node will publish a zeroconf record of type `_liquid._tcp.local`, with the
following txt field:

    "liquid_hostname=the-hostname.liquid"

[The python-zeroconf](https://github.com/jstasiak/python-zeroconf) library does
the conversion between this data format and python dicts.


### The discovery

After a short time, the `avahi-daemon` instance of each node will discover the
other instances and their services. By using python-zeroconf, each node
receives notifications when other nodes appear and dissapear from the network.
The module stores all the discovered nodes in a memory store (implemented as a
python dict at the time of writing).


### The JSON endpoint

Each node has a JSON endpoint at `localhost:13777` that lists all the nodes
that it has discovered on the network, including itself.

For example, node "one", if alone on a network with interface `eth0`, will have
the following JSON response:

    ```json
    {
      "enp0s3": {
        "li-vagrant-box-one-liquid._liquid._tcp.local.": {
          "address": "10.0.0.20",
          "discovered_at": "2017-07-22T15:52:23.961552",
          "hostname": "vagrant-box-one.liquid",
          "is_local": true
        }
      }
    }
    ```


### Updating local DNS server records (for the user devices (laptops))

Each node has a `dnsmasq` DNS server installed and running.

The events that the `python-zeroconf` picks up are filtered automatically by
only keeping `_liquid._tcp.local` services that have a `liquid_hostname` key in
their `txt` (`properties` in `python-zeroconf`) zeroconf field.  Also, each
node discovered has to be manually confirmed by the node administrator from the
`liquid-core` interface.

The `discover` instance inserts a record into its DNS server for each
discovered and confirmed node.

Dnsmasq does not support dynamic updating of DNS records. This means on each
event the Dnsmasq server will have to be restarted (which requires root
access). Dnsmasq is configured to use `/var/liquid/dns/dns.conf` as a
configuration file. The `liquid-core` service is being run by the `liquid`
user, that has write access to the `/var/liquid/dns/dns.conf` file.

Each time the list of discovered and confirmed nodes changes, the `liquid-core`
service rewrites the `dns.conf` file. When the `dns.conf` file is changed, the
changes are picked up by a daemon running `inotifywait` and Dnsconf gets
restarted.
