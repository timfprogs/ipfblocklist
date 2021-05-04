#!/usr/bin/perl

###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

#enable only the following on debugging purpose
use strict;
use warnings;
use CGI qw/:standard/;
use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

#Initialize variables and hashes

my $settings  = "${General::swroot}/blocklist/settings";
my $status    = "${General::swroot}/blocklist/status";
my $sources   = "${General::swroot}/blocklist/sources";
my $getipstat = '/usr/local/bin/getipstat';
my $version   = 1;
my %cgiparams=();
my $errormessage='';
my %color;
my %settings;
my %status;
my %sources;
my %stats;

#Read all parameters for site
&Header::getcgihash( \%cgiparams);
&General::readhash( "/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color );

#Show Headers
&Header::showhttpheaders();

General::readhash($settings, \%settings) if ( -r $settings );
General::readhash($status,   \%status)   if ( -r $status );
eval qx|/bin/cat $sources|               if ( -r $sources);

system( $getipstat );

#ACTIONS

if ($cgiparams{'ACTION'} eq "$Lang::tr{'save'}")
{
  #SaveButton on configsite

  my %new_settings = ();

  $new_settings{'ENABLE'}  = 'off';
  $new_settings{'TIMEOUT'} = 1209600, # 2 weeks
  $new_settings{'DEBUG'}   = 0;

  foreach my $item (keys %sources)
  {
    $new_settings{$item} = 'off';
  }

  foreach my $item (keys %cgiparams)
  {
    $new_settings{$item} = 'on' if (exists $new_settings{$item});
  }

  $new_settings{'RATE'}    = $cgiparams{'RATE'};
  $new_settings{'VERSION'} = $version;

  General::writehash($settings, \%new_settings);

  if(!$errormessage)
  {
      # Clear hashes
  }
  else
  {
    $cgiparams{'update'}='on';
  }
  %settings = %new_settings;
}

# Get blocklist statistics

unlink( '/var/tmp/iptablesmangle.txt' );
unlink( '/var/tmp/iptablesnat.txt' );

open STATS, '<', '/var/tmp/iptables.txt' or die "Can't open IP Tables stats file: $!";

foreach my $line (<STATS>)
{
  next unless ($line =~ m/_BLOCK/);

  my ($pkts, $bytes, $chain) = $line =~ m/^\s+(\d+\w?)\s+(\d+\w?)\s+(\w+)_BLOCK/;

  $stats{$chain} = [ $pkts, $bytes ];
}

close STATS;

unlink( '/var/tmp/iptables.txt' );

#Show site
&configsite;

#FUNCTIONS
sub configsite
{
  #find preselections
  my $enable = 'checked';

  # Open site

  Header::openpage($Lang::tr{'blocklists'}, 1, '');
  Header::openbigbox('100%', 'left');
  error();
  Header::openbox('100%', 'left', $Lang::tr{'blocklist config'});

  #### JAVA SCRIPT ####
  print<<END;
<script>
  \$(document).ready(function()
  {
    // Show/Hide elements when ENABLE checkbox is checked.
    if (\$("#ENABLE").attr("checked")) {
      \$(".sources").show();
    } else {
      \$(".sources").hide();
    }

    // Toggle Source list elements when "ENABLE" checkbox is clicked
    \$("#ENABLE").change(function() {
      \$(".sources").toggle();
    });
  });
</script>
END
;
  ##### JAVA SCRIPT END ####

  # Enable checkbox

  if ($settings{'ENABLE'} eq 'on')
  {
    $enable = 'checked';
  }
  else
  {
    $enable = '';
  }
  print<<END;
  <form method='post' action='$ENV{'SCRIPT_NAME'}'>
  <table style='width:100%' border='0'>
  <tr>
    <td style='width:24em'>$Lang::tr{'blocklist use blocklists'}</td>
    <td><label><input type='checkbox' name='ENABLE' id='ENABLE' $enable></label></td>
  </tr>
  </table><br>

END
;

  # The following are only displayed if the blocklists are enabled

  my $slow_selected   = $settings{'RATE'} eq 'SLOW'   ? "selected='selected'" : '';
  my $medium_selected = $settings{'RATE'} eq 'MEDIUM' ? "selected='selected'" : '';
  my $fast_selected   = $settings{'RATE'} eq 'FAST'   ? "selected='selected'" : '';

  print <<END
<div class='sources'>
  <table style='width:100%' border='0'>
  <tr>
    <td style='width:24em'>$Lang::tr{'blocklist check rate'}</td>
    <td>
        <select name='RATE' style='width:22em;'>
          <option value='SLOW' $slow_selected>$Lang::tr{'blocklist slow'}</option>
          <option value='MEDIUM' $medium_selected>$Lang::tr{'blocklist medium'}</option>
          <option value='FAST' $fast_selected>$Lang::tr{'blocklist fast'}</option>
        </select>
    </td>
  </tr>
  </table>
  <br />
  <table width='100%' cellspacing='1'>
  <tr>
    <th align='left'>$Lang::tr{'blocklist id'}</th>
    <th align='left'>$Lang::tr{'blocklist name'}</th>
    <th align='center'>$Lang::tr{'blocklist safe'}</th>
    <th align='center'>pkts</th>
    <th align='center'>bytes</th>
    <th align='center'>$Lang::tr{'blocklist updated'}</th>
    <th align='center'>$Lang::tr{'blocklist enable'}</th>
  </tr>
END
;

  # Iterate through the list of sources

  foreach my $source (sort keys %sources)
  {
    my $updated = '&nbsp;';
    my $name    = escapeHTML( $sources{$source}{'name'} );
    my $safe    = $Lang::tr{$sources{$source}{safe}};
    my $pkts    = '&nbsp;';
    my $bytes   = '&nbsp;';

    if (exists $stats{$source})
    {
      ($pkts, $bytes) = @{ $stats{$source} };
    }

    if ($settings{$source} eq 'on')
    {
      $enable = 'checked'
    }
    else
    {
      $enable = '';
    }

    if (exists $status{$source} and $status{$source} > 0)
    {
      $updated = localtime( $status{$source} );
    }

    print<<END
    <tr>
    <td><a href='$sources{$source}{info}' target='_blank'>$source</a></td>
    <td>$name</td>
    <td align='center'>$safe</td>
    <td align='right'>$pkts</td>
    <td align='right'>$bytes</td>
    <td align='center'>$updated</td>
    <td align='center'><label><input type='checkbox' name="$source" id="$source" $enable></label></td>
    </tr>\n
END
;
  }

    # The save button at the bottom of the page

    print<<END;
    </table>
    </div>
    <table style='width:100%;'>
    <tr>
        <td colspan='3' display:inline align='right'><input type='submit' name='ACTION' value='$Lang::tr{'save'}'></td>
    </tr>
    </table>
    <br>
    </form>
</div>
END
;
   Header::closebox();
   Header::closebigbox();
   Header::closepage();
  exit 0;
}


sub error
{
  if ($errormessage)
  {
    Header::openbox('100%', 'left', $Lang::tr{'error messages'});
    print "<class name='base'>$errormessage\n";
    print "&nbsp;</class>\n";
    Header::closebox();
  }
}
