#! /bin/bash

# Locations of settings files
updatedir="/var/ipfire/blocklist"
temp_dir="$TMP"
top="/home/tim/Programs/Block/temp"

phase2="no"

# Default update settings

VERSION=0

if [[ ! -d $updatedir ]]; then mkdir -p $updatedir; fi

# If there's an old settings file, read it and use it as the defaults
if [[ -e $updatesettings ]]; then
  echo read old settings
  source $updatesettings
fi

while getopts ":2hH" opt; do
  case $opt in
  2) phase2="yes";;

  *) echo "Usage: $0 [-2]"; exit 1;;
  esac
done

if [[ $phase2 == "no" ]]; then
  # Check to see if there's a new version available

  echo Check for new version

  wget "https://github.com/timfprogs/ipfblocklist/raw/master/VERSION"

  NEW_VERSION=`cat VERSION`
  rm VERSION

  # Set phase2 to yes to stop download of update

  if [[ $VERSION -eq $NEW_VERSION ]]; then
    phase2="yes"
  fi
fi

if [[ $phase2 == "no" ]]; then

# Download the manifest

  wget "https://github.com/timfprogs/ipfblocklist/raw/master/MANIFEST"

  # Download and move files to their destinations

  echo Downloading files

  if [[ ! -r MANIFEST ]]; then
    echo "Can't find MANIFEST file"
    exit 1
  fi

  while read -r name path owner mode || [[ -n "$name" ]]; do
    echo --
    echo Download $name
    path=$top/$path
    echo $path
    if [[ ! -d $path ]]; then mkdir -p $path; fi
    if [[ $name != "." ]];
    then
      wget "https://github.com/timfprogs/ipfblocklist/raw/master/$name" -O $path/$name
      chown $owner $path/$name
      chmod $mode $path/$name;
    else
      chown $owner $path
      chmod $mode $path;
    fi
  done < "MANIFEST"

  # Tidy up

  rm MANIFEST

  # Run the second phase of the new install file
  exec $0 -2

  echo Failed to exec $0
fi

start=$(($RANDOM % 40 + 5))
stop=$(($start + 10))
CRONTAB="%hourly,nice(1),random,serialonce(true) $start-$stop /usr/local/bin/snort-update.pl"

# Update the crontab

fcrontab -l >fcrontab_old

if grep blocklist fcrontab_old >>/dev/null; then
  sed -i "/blocklist.pl/c$CRONTAB" fcrontab_old;
else
  cat <<END >> fcrontab_old

# Snort rule update
$CRONTAB
END
fi

fcrontab fcrontab_old

# Update language cache

update-lang-cache

# Add link to startup

if [[ ! -e /etc/rc.d/rcsysinit.d/S86blocklist ]]; then
  ln -s /etc/rc.d/rc.init/ipblocklist  /etc/rc.d/rcsysinit.d/S86blocklist;
fi
