package pf::jsonAPI;

=head1 NAME

WebAPI - Apache mod_perl wrapper to PFAPI (below).

=cut

use strict;
use warnings;

use Apache2::RequestRec;
use Apache2::Request;
use Apache2::RequestIO;
use Apache2::RequestUtil;

use Apache2::Const -compile => qw(OK);
use Log::Log4perl;
use JSON;
use Data::Dumper;

use pf::config;
use pf::SwitchFactory;
use pf::inline::custom;

Log::Log4perl->init_and_watch("$conf_dir/log.conf", $LOG4PERL_RELOAD_TIMER);
Log::Log4perl::MDC->put('proc', 'pf::jsonAPI');



sub handler {
    my ($r) = @_;
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    if (defined($r->headers_in->{Request})) {
        $r->user($r->headers_in->{Request});
    }

    my $cont_len;
    $cont_len = $r->headers_in->{'Content-length'};

    my $content = "";
    if ( $cont_len > 0 ) {
        my $buf;

        $content .= $buf while ( $r->read( $buf, $cont_len ) > 0 );
    }

    my $text = decode_json($content);
    $logger->warn($content);
    $logger->warn(Dumper $text);


    $r->pnotes->{info} = $text;
    $r->handler('modperl');
    $r->set_handlers(PerlCleanupHandler => dispatch_request($r->headers_in->{Request}));
    return Apache2::Const::OK;
}

sub dispatch_request {
    my ($request) = @_;
    my $logger = Log::Log4perl::get_logger('pf::jsonAPI');

    my $key = {
        ReAssign     => \&ReAssignVlan,
        desAssociate => \&desAssociate,
        firewall     => \&firewall,
        snmptrap     => \&snmptrap,
        firewallsso => \&firewallsso,
    };
    return $key->{$request};
}

sub ReAssignVlan {
    my $r      = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info   = $r->pnotes->{info};
    my $switch = pf::SwitchFactory->getInstance()->instantiate( $info->{'switch'} );

    if ( defined( $info->{'connection_type'} )
        && ( $info->{'connection_type'} == $WIRED_802_1X || $info->{'connection_type'} == $WIRED_MAC_AUTH ) )
    {
        my ( $switchdeauthMethod, $deauthTechniques )
            = $switch->wiredeauthTechniques( $switch->{_deauthMethod}, $info->{'connection_type'} );
        $deauthTechniques->( $info->{'switch'}, $info->{'ifIndex'}, $info->{'mac'} );
    }
}

sub desAssociate {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};
    my $switch = pf::SwitchFactory->getInstance()->instantiate($info->{'switch'});

    my ($switchdeauthMethod, $deauthTechniques) = $switch->deauthTechniques($switch->{'_deauthMethod'},$info->{'connection_type'});

    $deauthTechniques->($switch,$info->{'mac'});
}

sub firewall {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};

    # verify if firewall rule is ok
    my $inline = new pf::inline::custom();
    $inline->performInlineEnforcement($info->{'mac'});
}

sub snmptrap {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};
    use Data::Dumper; $logger->warn(Dumper $info);

}

sub firewallsso {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};
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
        my $return = $firewall->action($firewall_conf,$info->{'method'},$info->{'mac'},$info->{'ip'});
    }
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2014 Inverse inc.

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

