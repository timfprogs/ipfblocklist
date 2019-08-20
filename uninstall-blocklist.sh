#! /bin/bash

echo Stopping ipblocklist from running

fcrontab -l >fcrontab_old

if grep "blocklist" fcrontab_old >>/dev/null; then
  sed -i "/blocklist\|IP block list update/,+2d" fcrontab_old;
fi

fcrontab fcrontab_old
rm fcrontab_old


echo Removing menu

rm -f /var/ipfire/menu/EX-blocklist.menu

echo Removing scripts

rm -f /etc/rc.d/init.d/ipblocklist
rm -f /srv/web/ipfire/cgi-bin/blocklist.cgi
rm -f /usr/local/bin/blocklist.pl
rm -f /srv/web/ipfire/cgi-bin/blocklist.cgi
rm -f /usr/share/logwatch/scripts/services/blocklist
rm -f /usr/share/logwatch/dist.conf/services/blocklist.conf

echo Removing settings

rm -fR /var/ipfire/blocklist
rm -f /etc/ipset/blocklist

echo Updating language files

rm -f /var/ipfire/addon-lang/blocklist.*
update-lang-cache
