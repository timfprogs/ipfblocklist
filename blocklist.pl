#! /usr/bin/perl

############################################################################
#                                                                          #
# IP Address blocklists for IPFire                                         #
#                                                                          #
# This is free software; you can redistribute it and/or modify             #
# it under the terms of the GNU General Public License as published by     #
# the Free Software Foundation; either version 2 of the License, or        #
# (at your option) any later version.                                      #
#                                                                          #
# This is distributed in the hope that it will be useful,                  #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU General Public License for more details.                             #
#                                                                          #
# You should have received a copy of the GNU General Public License        #
# along with IPFire; if not, write to the Free Software                    #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA #
#                                                                          #
# Copyright (C) 2018                                                       #
#                                                                          #
############################################################################
#                                                                          #
# This script can work in two modes; either standalone, in which case it   #
# uses the Emerging Threats FWRule list, or can can take a file containing #
# blocklist details in /var/ipfire/blocklist/sources as well as            #
# /var/ipfire/settings containing an enable/disable flag for each source.  #
#                                                                          #
# For each enabled source, two IPTables chains are created, one containing #
# the list of IP addresses to be blocked and the other to log the drop. If #
# the source is disabled these chains will be deleted.                     #
#                                                                          #
# The modification time is read for each source, and if necessary the list #
# is downloaded.  The downloaded list is compared to the existing IPTables #
# rules, and rules created or deleted as necessary.                        #
#                                                                          #
# To delete the created IPTables entries, run this script passing it the   #
# parameter 'stop'.                                                        #
#                                                                          #
############################################################################

use strict;
use warnings;

use Carp;
use Sys::Syslog qw(:standard :macros);
use HTTP::Request;
use LWP::UserAgent;

require "/var/ipfire/general-functions.pl";

############################################################################
# Configuration variables
#
# These variables give the locations of various files used by this script
############################################################################

my $dir            = "/var/ipfire/blocklist";
my $settings       = "$dir/settings";
my $sources        = "$dir/sources";
my $status         = "$dir/status";
my $iptables_list  = "/var/tmp/iptables.txt";
my $iptables_mangle= "/var/tmp/iptablesmangle.txt";
my $iptables_nat   = "/var/tmp/iptablesnat.txt";
my $getipstat      = "/usr/local/bin/getipstat";
my $iptables       = "/sbin/iptables";
my $ipset          = "/usr/sbin/ipset";
my $proxy_settings = "${General::swroot}/proxy/settings";
my $savedir        = "/etc/ipset/blocklist";
my $red_setting    = "/var/ipfire/red/iface";
my $tmp_dir        = "/var/tmp";
my $detailed_log   = "$tmp_dir/blocklist_log.txt";

# Default settings
# Should be overwritten by reading settings files

my %sources  = ( 'EMERGING_FWRULE' => { 'name'    => 'Emerging Threats Blocklist',
                                        'url'     => 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                                        'enable'  => 1,
                                        'parser'  => 'text_with_hash_comments' } );

my %settings = ( 'EMERGING_FWRULE' => 'on',
                 'DEBUG'           => 0);

############################################################################
# Function prototypes
############################################################################

sub do_update();
sub do_start();
sub do_stop();
sub do_delete();
sub get_ipsets( );
sub create_chain( $ );
sub delete_chain( $ );
sub update_source( $ );
sub download_blocklist( $ );
sub read_ipset( $ );
sub parse_text_with_hash_comments( $ );
sub parse_text_with_hash_comments( $ );
sub parse_text_with_semicolon_comments( $ );
sub parse_dshield( $ );
sub is_connected();
sub abort( $ );
sub log_message( $$ );
sub debug( $$ );

############################################################################
# Variables
############################################################################

my %chains;                   # The Blocklist IPSets already loaded
my @new_blocklist;            # IP Addresses and/or networks downloaded for
                              # current blocklist
my %old_blocklist;            # Already blocked IP Addresses and/or networks
                              # downloaded for current blocklist
my $update_status  = 0;       # Set to 1 to update status file
my %status;                   # Status information
my $red_iface;                # Name of red interface
my $hours          = int( time() / 3600 );
my %proxy_settings = ( 'UPSTREAM_PROXY' => '' );         # No Proxy in use

my %parsers  = ( 'text_with_hash_comments'      => \&parse_text_with_hash_comments,
                 'text_with_semicolon_comments' => \&parse_text_with_semicolon_comments,
                 'dshield'                      => \&parse_dshield );

############################################################################
# Set up for update
############################################################################

mkdir $dir unless (-d $dir);

# Connect to the system log

openlog( "blocklist", "nofatal", LOG_USER);
log_message LOG_INFO, "Starting IP Blocklist processing";

# Read settings

General::readhash( $settings, \%settings )             if (-e $settings);
General::readhash( $status,   \%status )               if (-e $status);
General::readhash( $proxy_settings, \%proxy_settings ) if (-e $proxy_settings);

if (-e $sources)
{
  debug 1, "Reading sources file";

  eval qx|/bin/cat $sources|;
}

# Find out what red interface is in use

open IN, '<', $red_setting or die "Can't open red inteface name file: $!";

$red_iface = <IN>;

close IN;

# Make sure the ip_set module is loaded

system( "modprobe ip_set" );

if (@ARGV)
{
  foreach my $cmd (@ARGV)
  {
    if ('update' =~ m/$cmd/i)
    {
      do_update();
    }
    elsif ('start' =~ m/$cmd/i)
    {
      do_start();
    }
    elsif ('stop' =~ m/$cmd/i)
    {
      do_stop();
    }
    elsif ('delete' =~ m/$cmd/i)
    {
      do_delete();
    }
    else
    {
      print "Usage: $0 [update|start|stop|delete]\n";
    }
  }
}
else
{
  do_update();
}


#------------------------------------------------------------------------------
# sub do_stop
#
# Deletes all the IPTables chains and the IPSets
#------------------------------------------------------------------------------

sub do_stop()
{
  # Get the list of current ipsets

  get_ipsets();

  log_message LOG_NOTICE, "Stopping blocklists";

  foreach my $source ( sort keys %sources )
  {
    if (exists $chains{$source})
    {
      delete_chain( $source );
    }
  }
}


#------------------------------------------------------------------------------
# sub do_start
#
# Recreates the IPTables chains and the IPSets from the saved values
#------------------------------------------------------------------------------

sub do_start()
{
  log_message LOG_NOTICE, "Starting blocklists";

  foreach my $source ( sort keys %sources )
  {
    if (-e "$savedir/$source.conf")
    {
      system( "$ipset restore -file $savedir/$source.conf" );
      create_chain( $source );
    }
  }
}


#------------------------------------------------------------------------------
# sub do_delete
#
# Deletes the IPTables chains, the IPSets and the saved values
#------------------------------------------------------------------------------

sub do_delete()
{
  # Get the list of current ipsets

  get_ipsets();

  log_message LOG_NOTICE, "Deleting blocklists";

  foreach my $source ( sort keys %sources )
  {
    if (exists $chains{$source})
    {
      delete_chain( $source );
    }

    if (-e "$savedir/$source.conf")
    {
      unlink "$savedir/$source.conf";
    }
  }

  unlink $status;
}


#------------------------------------------------------------------------------
# sub do_update
#
# Updates all the blocklists.
# Creates or deletes the blocklist firewall rules as necessary and checks for
# updates to the blocklists.
#------------------------------------------------------------------------------

sub do_update()
{
  return unless (is_connected());

  my $index = 0;

  # Get the list of current ipsets

  get_ipsets();

  # Check sources

  debug 1, "Checking blocklist sources";

  foreach my $source ( sort keys %sources )
  {
    @new_blocklist = ();
    $index++;
    my $name    = $sources{$source}{'name'};
    my $enabled = $sources{$source}{'enable'} eq 'on';
    my $rate    = $sources{$source}{'rate'};

    $rate *= 2 if ($settings{'RATE'} eq 'MEDIUM');
    $rate *= 4 if ($settings{'RATE'} eq 'SLOW');

    if (exists $settings{$source})
    {
      $enabled = $settings{$source} eq 'on';
    }

    debug 2, "Checking blocklist source: $name";

    if ($enabled)
    {
      if (not exists $chains{$source})
      {
        download_blocklist( $source );
        next unless (@new_blocklist);

        # Create the new ipset
        system( "$ipset create $source hash:net" ) == 0 or
          abort "Could not create ipset $source: $!";

        create_chain( $source );
      }

      # Limit the check rate

      if (($hours % $rate) == ($index % $rate))
      {
        download_blocklist( $source ) unless (@new_blocklist);
      }

      next unless (@new_blocklist);

      update_source( $source );
    }
    elsif (exists $chains{$source})
    {
      delete_chain( $source );

      delete $status{$source};
      $update_status  = 1;
    }
  }

  # Check for any deleted chains

  foreach my $chain (keys %chains)
  {
    if (not exists $sources{$chain})
    {
      delete_chain( $chain );

      delete $status{$chain};
      $update_status  = 1;
    }
  }

  if ($update_status)
  {
    debug 1, "Writing updated status file";

    General::writehash( $status, \%status );
  }

  log_message LOG_INFO, "Completed IP Blocklist update";
}


#------------------------------------------------------------------------------
# sub is_connected()
#
# Checks that the system is connected to the internet.
#
# This looks for a file created by IPFire when connected to the internet
#------------------------------------------------------------------------------

sub is_connected()
{
  return (-e "${General::swroot}/red/active");
}


#------------------------------------------------------------------------------
# sub create_chain( chain )
#
# Creates a new IPTables chain for a blocklist source.
#
# Note that we actually create two chains:
#   <NAME> contains the rules to recognise the blocked IP addresses and jump to
#   <NAME>_BLOCK which logs the block and then drops the connection.
#
# Parameters:
#   chain  The name of the blocklist
#------------------------------------------------------------------------------

sub create_chain( $ )
{
  my ($chain) = @_;

  log_message LOG_INFO, "Create IPTables chains for blocklist $chain";

  # Create new chains in filter table

  system( "$iptables -N $chain" ) == 0 or
    abort "Could not create IPTables chain $chain";

  system( "$iptables -N ${chain}_BLOCK" ) == 0 or
    abort "Could not create IPTables chain ${chain}_BLOCK";

  # Add the logging and drop rules

  system( "$iptables -A ${chain}_BLOCK -j LOG -m limit --limit 10/minute --limit-burst 5 --log-level 4 --log-prefix 'DROP_$chain'" ) == 0 or
    abort "Could not create IPTables chain $chain LOG rule";

  system( "$iptables -A ${chain}_BLOCK -j DROP" ) == 0 or
    abort "Could not create IPTables chain $chain drop rule";

  # Add the rule to check against the set

  system( "$iptables -A $chain -p ALL -m set --match-set $chain src -j ${chain}_BLOCK" );

  # Insert the address list chain into the main FORWARD and INPUT chains

  system( "$iptables -I FORWARD 1 -i $red_iface -j $chain" ) == 0 or
    abort "Could not insert IPTables $chain block chain into FORWARD table";

  system( "$iptables -I INPUT 1 -i $red_iface -j $chain" ) == 0 or
    abort "Could not insert IPTables $chain block chain into INPUT table";
}


#------------------------------------------------------------------------------
# sub delete_chain( chain )
#
# Deletes an IPTables chain when a blocklist source is disabled
#
# Parameters:
#   chain  The name of the blocklist
#------------------------------------------------------------------------------

sub delete_chain( $ )
{
  my ($chain) = @_;

  log_message LOG_INFO, "Delete IPTables chains for blocklist $chain";

  # Remove the blocklist chains from the main FORWARD and INPUT chains

  system( "$iptables -D INPUT -i $red_iface -j $chain" ) == 0 or
    log_message LOG_ERR, "Could not remove IPTables $chain block chain from INPUT table";

  system( "$iptables -D FORWARD -i $red_iface -j $chain" ) == 0 or
    log_message LOG_ERR, "Could not remove IPTables $chain block chain from FORWARD table";

  # Flush and delete the chains

  system( "$iptables -F $chain" ) == 0 or
    log_message LOG_ERR, "Could not flush IPTables chain $chain";

  system( "$iptables -F ${chain}_BLOCK" ) == 0 or
    log_message LOG_ERR, "Could not flush IPTables chain ${chain}_BLOCK";

  system( "$iptables -X $chain" ) == 0 or
    log_message LOG_ERR, "Could not delete IPTables chain $chain";

  system( "$iptables -X ${chain}_BLOCK" ) == 0 or
    log_message LOG_ERR, "Could not delete IPTables chain ${chain}_BLOCK";

  # Flush and delete the sets

  system( "$ipset flush $chain" ) == 0 or
    log_message LOG_ERR, "Could not flush ipset ${chain}";

  system( "$ipset destroy $chain" ) == 0 or
    log_message LOG_ERR, "Could not delete ipset ${chain}";

  # Delete the save file

  unlink "$savedir/$chain.conf" if (-e "$savedir/$chain.conf");
}


#------------------------------------------------------------------------------
# sub download_blocklist( chain )
#
# Updates the IP Addresses for a blocklist.  Depending on the blocklist one of
# two methods are used:
#
# - For some lists the header is downloaded and the modification date checked.
#   If newer than the existing list, the update is downloaded.
# - For other lists this is not supported,so the whole file has to be
#   downloaded regardless.
#
# Once downloaded the list is parsed to get the IP addresses and/or networks.
#
# Parameters:
#   chain  The name of the blocklist
#------------------------------------------------------------------------------

sub download_blocklist( $ )
{
  my ($chain)    = @_;
  my $wget_proxy = '';

  # Check the parser for the blocklist

  if (not exists $parsers{ $sources{$chain}{'parser'} })
  {
    log_message LOG_ERR, "Can't find parser $sources{$chain}{'parser'} for $chain blocklist";
    return;
  }

  my $parser = $parsers{ $sources{$chain}{'parser'} };

  debug 1, "Checking for blocklist $chain update";

  # Create a user agent for downloading the blocklist

  my $ua = LWP::UserAgent->new( max_size => 1024000 );

  # Get the Proxy settings

  if ($proxy_settings{'UPSTREAM_PROXY'})
  {
    my ($peer, $peerport) = (/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/);

    if ($peer)
    {
      $ua->proxy( "html", "http://$peer:$peerport/" );
    }

    $wget_proxy = "--proxy=on --proxy-user=$proxy_settings{'UPSTREAM_USER'} --proxy-passwd=$proxy_settings{'UPSTREAM_PASSWORD'} -e http_proxy=http://$peer:$peerport/";
  }

  if ($sources{$chain}{'method'} eq 'check-header-time')
  {
    # Get the blocklist modification time from the internet

    my $request  = HTTP::Request->new(HEAD => $sources{$chain}{'url'});
    my $response = $ua->request($request);

    if (not $response->is_success)
    {
      log_message LOG_WARNING, "Failed to download $chain header $sources{$chain}{'url'}: ". $response->status_line;

      return;
    }

    # Has the blocklist been modified since we last read it?

    if (exists $status{$chain} and $status{$chain} >= $response->last_modified)
    {
      # We've already got this version of the blocklist

      debug 1, "Blocklist $chain not modified";
      return;
    }

    debug 1, "Blocklist $chain Modification times: old $status{$chain}, new " . $response->last_modified;

    # Download the blocklist

    $request  = HTTP::Request->new(GET => $sources{$chain}{'url'});
    $response = $ua->request($request);

    if (not $response->is_success)
    {
      log_message LOG_WARNING, "Failed to download $chain blocklist $sources{$chain}{'url'}: ". $response->status_line;

      return;
    }

    $status{$chain} = $response->last_modified;
    $update_status  = 1;

    foreach my $line (split /[\r\n]+/, $response->content)
    {
      chomp $line;

      my $address = &$parser( $line );

      next unless ($address =~ m/\d+\.\d+\.\d+\.\d+/);

      push @new_blocklist, $address;
    }
  }
  else
  {
    # Can't use LWP:UserAgent, so try wget instead

    my $status = system( "wget $wget_proxy --no-show-progress -o $detailed_log -O $tmp_dir/blocklist $sources{$chain}{'url'}" );

    if ($status != 0)
    {
      log_message LOG_WARNING, "Failed to download $chain blocklist $sources{$chain}{'url'}: $status";
      return;
    }

    my @file_info = stat( "$tmp_dir/blocklist" );

    if (exists $status{$chain} and $status{$chain} >= $file_info[9])
    {
      # We've already got this version of the blocklist

      debug 1, "Blocklist $chain not modified";
      unlink "$tmp_dir/blocklist";
      return;
    }

    open LIST, '<', "$tmp_dir/blocklist" or abort "Can't open downloaded blocklist for $chain: $!";

    $status{$chain} = $file_info[9];
    $update_status  = 1;

    foreach my $line (<LIST>)
    {
      chomp $line;

      my $address = &$parser( $line );

      next unless ($address =~ m/\d+\.\d+\.\d+\.\d+/);

      push @new_blocklist, $address;
    }

    close LIST;

    unlink "$tmp_dir/blocklist";
  }
}


#------------------------------------------------------------------------------
# sub read_ipset( chain )
#
# Reads the existing contents of the set
#
# Parameters:
#   chain  The name of the blocklist
#------------------------------------------------------------------------------

sub read_ipset( $ )
{
  my ($chain)    = @_;
  %old_blocklist = ();

  debug 2, "Reading existing ipset for blocklist $chain";

  foreach my $line (qx/$ipset list $chain/)
  {
    next unless ($line =~ m|(\d+\.\d+\.\d+\.\d+(?:/\d+))|);

    my $address = $1;
    $address .= "/32" if ($address !~ m|/\d+|);

    $old_blocklist{$address} = 1;
  }
}


#------------------------------------------------------------------------------
# sub update_source( chain )
#
# Updates the IP Addresses for a blocklist
#
# The new list is compared to the existing list and new entries added or old
# entries deleted as necessary.
#
# Parameters:
#   chain  The name of the blocklist
#------------------------------------------------------------------------------

sub update_source( $ )
{
  my ($chain) = @_;

  debug 2, "Checking for $chain blocklist update from $sources{$chain}{'url'}";

  log_message LOG_INFO, "Updating $chain blocklist";

  read_ipset( $chain );

  # Process the blocklist

  foreach my $address ( @new_blocklist )
  {
    # We've got an address.  Add to set if it's new

    if (exists $old_blocklist{$address})
    {
      delete $old_blocklist{$address};
    }
    else
    {
      system( $ipset, 'add', $chain, $address, '-exist' ) == 0 or
        log_message LOG_WARNING, "Can't add address $address to set $chain";
    }

    debug 3, "Add net $address to blocklist $chain";
  }

  # Delete old entries that aren't needed any more

  debug 2, "Removing deleted rules from IPTables chain for blocklist $chain";

  foreach my $address ( keys %old_blocklist )
  {
    system( $ipset, 'del', $chain, $address ) == 0 or
      log_message LOG_WARNING, "Can't delete address $address from set $chain";

    debug 3, "Delete old net $address from blocklist $chain";
  }

  # Save the blocklist

  mkdir "$savedir" unless (-d "$savedir" );

  system( "$ipset save $chain > $savedir/$chain.conf" ) == 0 or
    log_message LOG_WARNING, "Can't save ipset $chain";
}


#------------------------------------------------------------------------------
# sub get_ipsets( )
#
# Gets a list of the current ipsets
#------------------------------------------------------------------------------

sub get_ipsets( )
{
  debug 1, "Reading list of existing ipsets";

  my @sets = qx($ipset -n list);

  # Parse the tables

  foreach my $line (<@sets>)
  {
    chomp $line;

    next unless ($line);

    $chains{$line} = 1;
  }
}


#------------------------------------------------------------------------------
# sub parse_text_with_hash_comments( line )
#
# Parses an input line removing comments.
#
# Parameters:
#   line  The line to parse
#
# Returns:
#   Either an IP Address or a null string
#------------------------------------------------------------------------------

sub parse_text_with_hash_comments( $ )
{
  my ($line) = @_;

  return "" if ($line =~ m/^\s*#/);

  $line =~ s/#.*$//;

  $line =~ m/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/;

  return $1;
}


#------------------------------------------------------------------------------
# sub parse_text_with_semicolon_comments( line )
#
# Parses an input line removing comments.
#
# Parameters:
#   line  The line to parse
#
# Returns:
#   Either and IP Address or a null string
#------------------------------------------------------------------------------

sub parse_text_with_semicolon_comments( $ )
{
  my ($line) = @_;

  return "" if ($line =~ m/^\s*;/);

  $line =~ s/;.*$//;

  $line =~ m/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/;

  return $1;
}


#------------------------------------------------------------------------------
# sub parse_dshield( line )
#
# Parses an input line removing comments.
#
# The format is:
# Start Addrs   End Addrs   Netmask   Nb Attacks   Network Name   Country   email
#
# Parameters:
#   line  The line to parse
#
# Returns:
#   Either and IP Address or a null string
#------------------------------------------------------------------------------

sub parse_dshield( $ )
{
  my ($line) = @_;

  return "" if ($line =~ m/^\s*#/);

  $line =~ s/#.*$//;

  $line =~ m/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)\s+\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+(\d+)/;

  return "$1/$2";
}


#------------------------------------------------------------------------------
# sub abort( message, parameters... )
#
# Aborts the update run, printing out an error message.
#
# Parameters:
#   message     Message to be printed
#------------------------------------------------------------------------------

sub abort( $ )
{
my ($message) = @_;

  log_message( LOG_ERR, $message );
  croak $message;
}


#------------------------------------------------------------------------------
# sub log_message( level, message )
#
# Logs a message.  If the script is run from a terminal messages are also
# output on STDOUT.
#
# Parameters:
#   level   Severity of message
#   message Message to be logged
#------------------------------------------------------------------------------

sub log_message( $$ )
{
  my ($level, $message) = @_;

  print "($level) $message\n" if (-t STDIN);
  syslog( $level, $message );
}


#------------------------------------------------------------------------------
# sub debug( level, message )
#
# Optionally logs a debug message.  If the script is run from a terminal, level
# 1 debug messages are output regardless of the debug setting.
#
# Parameters:
#   level   Debug level
#   message Message to be logged
#------------------------------------------------------------------------------

sub debug( $$ )
{
  my ($level, $message) = @_;

  if (($level <= $settings{'DEBUG'}) or
      ($level == 1 and -t STDIN))
  {
    log_message LOG_DEBUG, $message;
  }
}
