#!/usr/bin/perl -w

=head1 NAME

extract_i18n_strings.pl - extract localizable strings

=head1 SYNOPSIS

=head1 DESCRIPTION

The script extracts the strings from the source code and the HTML templates that
can be localized.

=cut

use File::Find;
use lib qw(/usr/local/pf/lib /usr/local/pf/html/pfappserver/lib);
use pf::action;
use pf::admin_roles;
use pf::Authentication::Source;
use pf::Authentication::constants;
use pf::Switch::constants;
use pfappserver::Controller::Graph;
use pfappserver::Model::Node;
use pfappserver::Form::Config::Wrix;
use pfappserver::Form::Portal::Common;
use pf::config;

use constant {
    APP => 'html/pfappserver',
    CONF => 'conf',
};

my %strings = ();
my %translations = ();

=head1 SUBROUTINES

=head2 add_string

Add a localizable sring to the list.

=cut

sub add_string {
    my ($string, $source) = @_;

    unless ($strings{$string}) {
        $strings{$string} = [];
    }
    unless (grep(/\Q$source\E/, @{$strings{$string}})) {
        push(@{$strings{$string}}, $source);
    }
}

=head2 add_translation

Add an existing English translation.

=cut

sub add_translation {
    my ($key, $value) = @_;

    $translations{$key} = $value;
}

=head2 parse_po

Parse the English PO file to extract existing translations because some keys are
translated even for English.

=cut

sub parse_po {
    my $file = APP.'/lib/pfappserver/I18N/i_default.po';

    my ($key, %msg);
    open (PO, $file);
    my $line;
    while (defined($line = <PO>)) {
        chomp $line;
        if ($line =~ m/^\s*\"(.+)\"$/) {
            if ($key) {
                $msg{$key} .= $1;
            }
        }
        elsif ($line =~ m/^(msgid|msgstr) \"(.*)\"$/) {
            if ($msg{msgid} && $msg{msgstr}) {
                add_translation($msg{msgid}, $msg{msgstr});
                delete $msg{msgid};
                delete $msg{msgstr};
            }
            elsif ($1 eq 'msgid') {
                delete $msg{msgstr};
            }
            $key = $1;
            $msg{$key} = $2;
        }
    }
    if ($msg{msgid} && $msg{msgstr}) {
        add_translation($msg{msgid}, $msg{msgstr});
    }
}

=head2 parse_tt

Extract localizable strings from TT templates.

=cut

sub parse_tt {
    my $dir = APP.'/root';
    my @templates = ();

    my $tt = sub {
        return unless -f && m/\.(tt|inc)$/;
        push(@templates, $File::Find::name);
    };

    find($tt, $dir);

    my $line;
    foreach my $template (@templates) {
        open(TT, $template);
        while (defined($line = <TT>)) {
            chomp $line;
            while ($line =~ m/\[\% l\(['"](.+?(?!\\))['"](,.*)?\) (\| js )?\%\]/g) {
                add_string($1, $template) unless ($1 =~ m/\${/);
            }
        }
        close(TT);
    }

    my $template = $dir . '/admin/configuration.tt';
    open(TT, $template);
    while (defined($line = <TT>)) {
        chomp $line;
        if ($line =~ m/\[\% ?list_entry\(\s*'[^']*',\s*'[^']*',\s*'([^']*)'\) ?\%\]/g) {
            add_string($1, $template);
        }
        elsif ($line =~ m/\[\% ?pf_section_entry\(\s*'[^']*',\s*'([^']*)'\) ?\%\]/g) {
            add_string($1, $template);
        }
    }
    close(TT);

    $template = $dir . '/admin/reports.tt';
    open(TT, $template);
    while (defined($line = <TT>)) {
        chomp $line;
        if ($line =~ m/\[\% ?list_entry\(\s*'[^']*',\s*'([^']*)'\) ?\%\]/g) {
            add_string($1, $template);
        }
    }
    close(TT);
}

=head2 parse_mc

Extract localizable strings from Models and Controllers classes.

=cut

sub parse_mc {
    my $base = APP.'/lib/pfappserver/';
    my @dir = qw/Base Controller Model/;
    my @modules = ();

    my $pm = sub {
        return unless -f && m/\.pm$/;
        push(@modules, $File::Find::name);
    };

    foreach my $path (@dir) {
        find($pm, $base . $path);
    }

    my $line;
    foreach my $module (@modules) {
        open(PM, $module);
        while (defined($line = <PM>)) {
            chomp $line;
            if ($line =~ m/\$c->loc\(['"](.+?[^'"\\])["']\)/) {
                my $string = $1;
                $string =~ s/\\'/'/g;
                add_string($string, $module);
            }
        }
        close(PM);
    }
}

=head2 parse_forms

Extract localizable strings from HTML::FormHandler classes.

=cut

sub parse_forms {
    my $dir = APP.'/lib/pfappserver/Form';
    my @forms = ();

    my $pm = sub {
        return unless -f && m/\.pm$/;
        push(@forms, $File::Find::name);
    };

    find($pm, $dir);

    my $line;
    foreach my $form (@forms) {
        open(PM, $form);
        while (defined($line = <PM>)) {
            chomp $line;
            if ($line =~ m/(?:label|required|help) => "(.+?[^\\])["]/ ||
                $line =~ m/(?:label|required|help) => '(.+?[^\\])[']/) {
                my $string = $1;
                $string =~ s/\\'/'/g;
                add_string($string, $form);
            }
        }
        close(PM);
    }
}

=head2 parse_conf

Extract sections, options and descriptions from documentation.conf.

=cut

sub parse_conf {
    my $file = CONF.'/documentation.conf';

    sub _format_description {
        my $description = join("\n", @{$_[0]});
        $description =~ s/</&lt;/g;     # convert < to HTML entity
        $description =~ s/>/&gt;/g;     # convert > to HTML entity
        $description =~ s/(\S*(&lt;|&gt;)\S*)(?=[\s,\.])/<code>$1<\/code>/g; # enclose strings that contain < or >
        $description =~ s/(\S+\.(html|tt|pm|pl|txt))\b(?!<\/code>)/<code>$1<\/code>/g; # enclose strings that ends with .html, .tt, etc
        $description =~ s/^ \* (.+?)$/<li>$1<\/li>/mg; # create list elements for lines beginning with " * "
        $description =~ s/(<li>.*<\/li>)/<ul>$1<\/ul>/s; # create lists from preceding substitution 
        $description =~ s/\"([^\"]+)\"/<i>$1<\/i>/mg; # enclose strings surrounded by double quotes
        $description =~ s/\[(\S+)\]/<strong>$1<\/strong>/mg; # enclose strings surrounded by brakets
        $description =~ s/(https?:\/\/\S+)/<a href="$1">$1<\/a>/g; # make links clickable
        $description =~ s/\"/\\\"/g;

        return $description;
    }

    my ($line, $section, @options, @desc);
    open(FILE, $file);
    while (defined($line = <FILE>)) {
        chomp $line;
        if ($line =~ m/^\[(([^\.]+).*?)\]$/) {
            if (scalar @desc) {
                add_string($2, $file);
                add_string($section, $file);
                add_string(_format_description(\@desc), "$file ($section)");
            }
            if (scalar @options) {
                map { add_string($_, "$file ($section options)") } @options;
            }
            @desc = ();
            @options = ();
            $section = $1;
        }
        elsif ($line =~ m/^options=(.*)$/) {
            @options = split(/\|/, $1);
        }
        elsif ($line =~ m/^description=/) {
            @desc = ();
            while (defined($line = <FILE>)) {
                chomp $line;
                last if ($line =~ m/^EOT$/);
                push(@desc, $line);
            }
        }
    }
    if (scalar @desc) {
        add_string($section, $file);
        add_string(_format_description(\@desc), "$file ($section)");
    }
    if (scalar @options) {
        map { add_string($_, "$file ($section options)") } @options;
    }
    close(FILE);
}

=head2 extract_modules

Extract various localizable strings from PacketFence modules.

=cut

sub extract_modules {
    my %strings = ();

    sub const {
        my ($module, $name, $arrayref) = @_;

        foreach (@$arrayref) {
            add_string($_, "$module ($name)");
        }
    }

    const('pf::config', 'VALID_TRIGGER_TYPES', \@pf::config::VALID_TRIGGER_TYPES);
    const('pf::config', 'Inline triggers', [$pf::config::MAC, $pf::config::PORT, $pf::config::SSID, $pf::config::ALWAYS]);
    const('pf::config', 'Network types', [$pf::config::NET_TYPE_VLAN_REG, $pf::config::NET_TYPE_VLAN_ISOL, $pf::config::NET_TYPE_INLINE, 'management', 'other']);

    my @values = map { "${_}_action" } @pf::action::VIOLATION_ACTIONS;
    const('pf::action', 'VIOLATION_ACTIONS', \@values);

    const('pf::admin_roles', 'Actions', \@ADMIN_ACTIONS);

    my $attributes = pf::Authentication::Source->common_attributes();
    my @common = map { $_->{value} } @$attributes;
    const('pf::Authentication::Source', 'common_attributes', \@common);
    my $types = pf::authentication::availableAuthenticationSourceTypes();
    foreach (@$types) {
        my $type = "pf::Authentication::Source::${_}Source";
        $type->require();
        my $source = $type->new
          ({
            id => '',
            usernameattribute => 'cn',
            client_secret => '',
            host => '',
            realm => '',
            secret => '',
            basedn => '',
            encryption => '',
            scope => '',
            path => '',
            client_id => ''
           });
        $attributes = $source->available_attributes();

        @values = map {
            my $value = $_->{value};
            ( grep {/$value/} @common ) ? () : $value
        } @$attributes;
        const($type, 'available_attributes', \@values) if (@values);
    }

    const('pf::Authentication::constants', 'Actions', \@Actions::ACTIONS);

    @values = map { @$_ } values %Conditions::OPERATORS;
    const('pf::Authentication::constants', 'Conditions', \@values);

    const('pf::Switch::constants', 'Modes', \@SNMP::MODES);

    const('pf::pfcmd::report', 'SQL', ['dhcp_fingerprint']);
    const('pf::pfcmd::report', 'report_nodebandwidth', [qw/acctinput acctoutput accttotal callingstationid/]);

    $attributes = pfappserver::Model::Node->availableStatus();
    const('pfappserver::Model::Node', 'availableStatus', $attributes);

    const('pfappserver::Controller::Graph', 'graph type', \@pfappserver::Controller::Graph::GRAPHS);

    const('pfappserver::Controller::Graph', 'os fields', [qw/description count/]);
    const('pfappserver::Controller::Graph', 'connectiontype fields', [qw/connection_type connections/]);
    const('pfappserver::Controller::Graph', 'ssid fields', [qw/ssid nodes/]);
    const('pfappserver::Controller::Graph', 'nodebandwidth fields', [qw/callingstationid/]);
    const('pfappserver::Controller::Graph', 'osclassbandwidth fields', [qw/dhcp_fingerprint/]);

    const('pfappserver::Form::Config::Wrix', 'open hours', \@pfappserver::Form::Config::Wrix::HOURS);

    @values = pfappserver::Form::Portal::Common->options_mandatory_fields();
    @values = map { $_->{label} } @values;
    const('pfappserver::Form::Portal::Common', 'mandatory fields', \@values);

    const('html/pfappserver/root/user/list_password.tt', 'options', ['mail_loading']);
}

=head2 print_po

Print the PO file constructed from the extracted localizable strings.

=cut

sub print_po {
    my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time);
    my $now = sprintf("%d-%02d-%02d %02d:%02d-0400", $year+1900, $mon+1, $mday, $hour, $min);

    open(RELEASE, CONF.'/pf-release');
    my $content = <RELEASE>;
    chomp $content;
    my ($package, $version) = $content =~ m/(\S+) ([\d\.]+)/;
    close(RELEASE);

    print <<EOT;
# English translations for $package package.
# Copyright (C) 2012-2014 Inverse inc.
# This file is distributed under the same license as the $package package.
#
msgid ""
msgstr ""
"Project-Id-Version: $version\\n"
"POT-Creation-Date: YEAR-MO-DA HO:MI+ZONE\\n"
"PO-Revision-Date: $now\\n"
"Last-Translator: Inverse inc. <info\@inverse.ca>\\n"
"Language-Team: English\\n"
"Language: en\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=ASCII\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\\n"

EOT

    foreach my $string (sort keys %strings) {
        foreach my $file (sort @{$strings{$string}}) {
            print "# $file\n";
        }
        my @lines = split("\n", $string);
        if (@lines > 1) {
            print "msgid \"\"\n";
            print join("\n", map { "  \"$_\"" } @lines), "\n";
        }
        else {
            print "msgid \"$string\"\n";
        }
        print "msgstr \"" . ($translations{$string} || '') . "\"\n\n";
    }
}

=head2 verify

Check if any translated string was not extracted. In this case, we need to
manually check if the string is still used.

=cut

sub verify {
    my @translated_keys = keys %translations;
    my @extracted_keys = keys %strings;

    my %seen;
    @seen {@translated_keys} = ( );
    delete @seen {@extracted_keys};

    my @translated_not_extracted = keys %seen;
    if (scalar @translated_not_extracted) {
        warn "The following keys were not extracted:\n\t" .
          join("\n\t", sort @translated_not_extracted) .
            "\n";
    }
}

#### MAIN ####

&parse_po;
&parse_tt;
&parse_mc;
&parse_forms;
&parse_conf;
&extract_modules;
&print_po;
&verify;

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2013 Inverse inc.

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

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
