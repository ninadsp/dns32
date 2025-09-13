## DNS 32

A work-in-progress DNS Adblocker powered by a low power ESP32 chip that sits in your home network, and saves you from distracting and manipulative ads.

Inspired by [esper](https://github.com/zachmorr/esper/), [ESP32_Adblocker](https://github.com/s60sc/ESP32_AdBlocker/), as well as the venerable [pi-hole](https://github.com/pi-hole/pi-hole) and other Raspberry Pi friendly projects.

This is currently being built as part of a [Recurse Center](https://recurse.com) batch project.

What currently works?

* Can boot an ESPWROOM32 dev board
* Checks if we have previously configured a wifi network's credentials
* If we have a stored network, we try to connect to it
* If we cannot connect to it, or we do not have a stored network, we switch to AP mode
* Users can connect with the `dns32.local` mdns address
* A user is prompted to choose from discovered wifi networks, and enter a password
* The password is stored, and the devices stops acting as an AP. It connects to the selected wifi network.
* It currently accepts DNS queries, and returns a static IP address


TODO:

* Fetch upstream DNS servers configured on the network's router during DHCP
* Implement a client for DNS queries that uses the configured upstreams
* Wire up the DNS query forwarding
* Store a deny list of domain names and read from it on start up
* During DNS query forwarding, check if we are requesting for a domain from this list, and return `127.0.0.1` in that case
* Revisit the dashboard and start showing basic statistics (uptime, network connection active, number of host list entries)
* Figure out how to periodically update the deny list