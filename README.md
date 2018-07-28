# ipfblocklist
IP Blocklists for IPFire

Provides a service to install and update IP blocklists on an IPFire appliance automatically.

## To install

1. First remove any blocklists that you've already got running.

2. Download the installer:

  ```wget https://github.com/timfprogs/ipfblocklist/raw/master/install-blocklist.sh```
  
3. Make it executable:

  ```chmod +x install-blocklist.sh```

4. Run the installer:

  ```./install-blocklist.sh```

The installer will download the files and install them in the correct places.  You can now go to the WUI (under 'Firewall') and
configure the addon.

## Notes
### Update check rate

The actual rate of checking for updates depends on the blocklist; the blocklists change at different rates and the providers of the
lists specify different maximum download rates.  If the 'Fast' option is selected the maxium check rate is once every hour and the
minimum once every day.  'Medium' doubles these periods and 'Slow' doubles them again.

Unless you expect to be a specific target 'Slow' should be adequate.

### Selection changes

If the selected blocklists are changed in the WUI the actual blocklists will not change immediately, but the next time the
updater runs.

### Blocklists

There are a wide variety of blocklists available which have different purposes.  It's unnecessary to enable all of them since
there's a lot of overlap.

Some of the lists are marked as 'Safe' in the WUI; these lists should not block any legitimate traffic.  They refer either to
invalid IP addresses or to IP addresses only used as a source of Malware.  Other lists may block legitimate traffic although
this may be acceptable if they are a source of Malware.

#### Bogon and Full Bogon

These lists block IP addresses that should not be seen on the public internet.  The Bogon list is now the same as the Martian
list since all IP address blocks have now been assigned to regional registries by IANA.  This list consists of the IP address
blocks reserved for special purposes, including the private network addresses 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
The full list adds address blocks that have not been assigned by regional registries or have been returned to them as no longer
in use.

These lists should only be used on the connection to the internet, and only then if the red interface does not connect via
a router using one of these addresses.  If you use these lists inside a network you will block your own traffic.

#### TOR

These lists block all TOR nodes or just TOR exit nodes.  If you're running an organisation that is subject to rules about
security or data protection you should probably use the exit node list, unless you have an actual need to use TOR.

#### Emerging FW rule

This is a composite list that contains items from other lists.  If you only want to use one list, this may be a good choice,
however if you're using multiple lists this will probably duplicate them.

At the time of writing it contained entries from the following other lists: Feodo, Zeus, Spamhaus DROP.

### Overlap

As an example of the amount of overlap between lists, the following table was calculated in mid July 2018.  Each list along
the top of the table will block the given number of entries from the list at the side of the table.

| |Abuse.ch C&C|Alienvault|Bogon|Ciarmy|Dshield|ET Compromised|ET FWrule|Feodo tracker|Full Bogon|Spamhaus DROP|Spamhaus EDROP|TOR exit|TOR full|Talos|Zeus BadIP|Zeus IP|
|------------|---|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
|Abuse.ch C&C|297|1|0|0|0|0|6|0|0|5|1|0|0|1|1|1|
|Alienvault|1|61867|0|14701|2852|236|2748|0|1|105|4|1|2|9|1|1|
|Bogon|0|0|14|0|0|0|0|0|14|0|0|0|0|0|0|0|
|Ciarmy|0|14701|0|15000|1487|63|1471|0|0|37|2|0|0|4|0|0|
|Dshield|0|0|0|0|20|0|18|0|0|1|0|0|0|0|0|0|
|ET Compromised|0|236|0|63|1|640|2|0|0|1|0|1|2|4|0|0|
|ET FWrule|1|1|0|0|18|0|2381|1421|0|849|6|0|0|76|102|108|
|Feodo tracker|0|0|0|0|0|0|1421|1422|0|0|0|0|0|6|0|0|
|Full Bogon|0|0|14|0|0|0|0|0|3366|0|0|0|0|0|0|0|
|Spamhaus DROP|0|0|0|0|1|0|843|0|0|831|6|0|0|0|0|0|
|Spamhaus EDROP|0|0|0|0|0|0|6|0|0|6|119|0|0|0|0|0|
|TOR exit|0|1|0|0|1|1|5|0|0|5|0|982|974|855|0|0|
|TOR full|0|2|0|0|1|2|10|0|0|8|0|974|6260|867|0|0|
|Talos|1|9|0|4|2|4|89|6|0|12|2|855|867|1595|69|70|
|Zeus BadIP|1|1|0|0|0|0|108|0|0|6|0|0|0|69|102|102|
|Zeus IP|1|1|0|0|0|0|114|0|0|6|0|0|0|70|102|108|

As an example, enabling the DShield list would duplicate 2852 of the entries in the Alienvault list.

The leading diagonal of the table gives the number of entries in each list.  Note that some of the lists use single IP
addresses whereas others use IP address blocks.

### Intrusion Detection System Rules

If you're running an Intrusion Detection System it's a good idea to disable any rules that implement IP blocklists.  An IDS is
not very efficient at blockling address lists, so disabling these rules will save memory and decrease the amount of processing
power required.  It's also likely that the majority of the IDS alerts are generated from these rules; disabling them will
stop these alerts from being logged and make it easier to see potential attacks that get through the firewall.

The rule groups that implement blocklists are:

|Source|Rules|
|------|-----|
|Talos VRT|blacklist.rules
|Emerging Threats|emerging-ciarmy.rules, emerging-compromised.rules, emerging-drop.rules, emerging-dshield.rules, emerging-tor.rules, emerging-botcc.rules, emerging-botcc.portgrouped.rules|
