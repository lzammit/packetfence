package pfappserver::Model::Config::Switch;

=head1 NAME

pfappserver::Model::Config::Switch add documentation

=cut

=head1 DESCRIPTION

pfappserver::Model::Config::Switch;

=cut

use Moose;
use namespace::autoclean;
use pf::config::cached;
use pf::config;
use pf::ConfigStore::Switch;
use HTTP::Status qw(:constants is_error is_success);

extends 'pfappserver::Base::Model::Config';

sub _buildConfigStore {return pf::ConfigStore::Switch->new;}

=head1 METHODS

=head2 remove

Delete an existing item

=cut

sub remove {
    my ($self,$id) = @_;
    if($id eq 'all') {
        return ($STATUS::INTERNAL_SERVER_ERROR, "Cannot delete this item");
    }
    return $self->SUPER::remove($id);
}

__PACKAGE__->meta->make_immutable;


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

1;

