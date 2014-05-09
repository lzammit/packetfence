package pf::WebAPI;

=head1 NAME

WebAPI - Apache mod_perl wrapper to PFAPI (below).

=cut

use strict;
use warnings;

use Apache2::MPM ();
use Apache2::RequestRec;
use Log::Log4perl;
use ModPerl::Util;

use pf::config;

#uncomment for more debug information
#use SOAP::Lite +trace => [ fault => \&log_faults ];
use SOAP::Transport::HTTP;
use pf::WebAPI::MsgPack;
use pf::WebAPI::JSONRPC;

Log::Log4perl->init_and_watch("$conf_dir/log.conf", $LOG4PERL_RELOAD_TIMER);
Log::Log4perl::MDC->put('proc', 'pf::WebAPI');

# set proper logger tid based on if we are run from mod_perl or not
if (exists($ENV{MOD_PERL})) {
    if (Apache2::MPM->is_threaded) {
        require APR::OS;
        # apache threads
        Log::Log4perl::MDC->put('tid', APR::OS::current_thread_id());
    } else {
        # httpd processes
        Log::Log4perl::MDC->put('tid', $$);
    }
} else {
    # process threads
    require threads;
    Log::Log4perl::MDC->put('tid', threads->self->tid());
}

my $server_soap = SOAP::Transport::HTTP::Apache->dispatch_to('PFAPI');
my $server_msgpack = pf::WebAPI::MsgPack->new({dispatch_to => 'PFAPI'});
my $server_jsonrpc = pf::WebAPI::JSONRPC->new({dispatch_to => 'PFAPI'});

sub handler {
    my ($r) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');
    if (defined($r->headers_in->{Request})) {
        $r->user($r->headers_in->{Request});
    }
    my $content_type = $r->headers_in->{'Content-Type'};
    $logger->debug("$content_type");
    if( $content_type eq 'application/x-msgpack') {
        return $server_msgpack->handler($r);
    } elsif (pf::WebAPI::JSONRPC::allowed($content_type)) {
        return $server_jsonrpc->handler($r);
    } else {
        return $server_soap->handler($r);
    }
}

sub log_faults {
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');
    $logger->info(@_);
}

package PFAPI;

=head1 NAME

PFAPI - Web Services handler exposing PacketFence features

=cut

use pf::config;
use pf::iplog;
use pf::radius::custom $RADIUS_API_LEVEL;
use pf::violation;
use pf::soh::custom $SOH_API_LEVEL;
use pf::util qw(valid_mac valid_ip);
use pf::locationlog;
use pf::ipset;

sub event_add {
  my ($class, $date, $srcip, $type, $id) = @_;
  my $logger = Log::Log4perl->get_logger('pf::WebAPI');
  $logger->info("violation: $id - IP $srcip");

  # fetch IP associated to MAC
  my $srcmac = ip2mac($srcip);
  if ($srcmac) {

    # trigger a violation
    violation_trigger($srcmac, $id, $type);

  } else {
    $logger->info("violation on IP $srcip with trigger ${type}::${id}: violation not added, can't resolve IP to mac !");
    return(0);
  }
  return (1);
}

sub echo {
    my ($class, @args) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');
    return @args;
}

sub radius_authorize {
  my ($class, %radius_request) = @_;
  my $logger = Log::Log4perl->get_logger('pf::WebAPI');

  my $radius = new pf::radius::custom();
  my $return;
  eval {
      $return = $radius->authorize(\%radius_request);
  };
  if ($@) {
      $logger->error("radius authorize failed with error: $@");
  }
  return $return;
}

sub radius_accounting {
  my ($class, %radius_request) = @_;
  my $logger = Log::Log4perl->get_logger(__PACKAGE__);

  my $radius = new pf::radius::custom();
  my $return;
  eval {
      $return = $radius->accounting(\%radius_request);
  };
  if ($@) {
      $logger->logdie("radius accounting failed with error: $@");
  }
  return $return;
}

sub soh_authorize {
  my ($class, %radius_request) = @_;
  my $logger = Log::Log4perl->get_logger('pf::WebAPI');

  my $soh = pf::soh::custom->new();
  my $return;
  eval {
    $return = $soh->authorize(\%radius_request);
  };
  if ($@) {
    $logger->error("soh authorize failed with error: $@");
  }
  return $return;
}

sub update_iplog {
    my ( $class, $srcmac, $srcip, $lease_length ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::iplog::iplog_update($srcmac, $srcip, $lease_length));
}

sub synchronize_locationlog {
    my ( $class, $switch, $switch_ip, $switch_mac, $ifIndex, $vlan, $mac, $voip_status, $connection_type, $user_name, $ssid ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::locationlog::locationlog_synchronize($switch, $switch_ip, $switch_mac, $ifIndex, $vlan, $mac, $voip_status, $connection_type, $user_name, $ssid));
}

sub insert_close_locationlog {
    my ($class, $switch, $switch_ip, $switch_mac, $ifIndex, $vlan, $mac, $connection_type, $user_name, $ssid);
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return(pf::locationlog::locationlog_insert_closed($switch, $switch_ip, $switch_mac, $ifIndex, $vlan, $mac, $connection_type, $user_name, $ssid));
}

sub open_iplog {
    my ( $class, $mac, $ip, $lease_length ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::iplog::iplog_open($mac, $ip, $lease_length));
}

sub close_iplog {
    my ( $class, $ip ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::iplog::iplog_close($ip));
}

sub close_now_iplog {
    my ( $class, $ip ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::iplog::iplog_close_now($ip));
}

sub trigger_violation {
    my ( $class, $mac, $tid, $type ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return (pf::violation::violation_trigger($mac, $tid, $type));
}

sub ipset_node_update {
    my ( $class, $oldip, $srcip, $srcmac ) = @_;
    my $logger = Log::Log4perl->get_logger('pf::WebAPI');

    return(pf::ipset::node_update($oldip, $srcip, $srcmac));
}

sub firewallsso {
    my ($class, $info) = @_;
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    foreach my $firewall_conf ( sort keys %ConfigFirewallSSO ) {
        $logger->warn($ConfigFirewallSSO{$firewall_conf}->{'type'});
        my $module_name = 'pf::firewallsso::'.$ConfigFirewallSSO{$firewall_conf}->{'type'};
        $module_name = untaint_chain($module_name);
        # load the module to instantiate
        if ( !(eval "$module_name->require()" ) ) {
            $logger->error("Can not load perl module: $@");
            return 0;
        }
        my $firewall = $module_name->new();
        $firewall->action($firewall_conf,$info->{'method'},$info->{'mac'},$info->{'ip'});
    }
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2013 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut
