package lib::XCoro::LWP;

use 5.10.0;

use strict;
use warnings;
no warnings 'experimental';

use Carp;
use LWP;
use base "LWP::UserAgent";

use lib::XCoro;

push @LWP::Protocol::http::EXTRA_SOCK_OPTS, (SendTE => 0);

sub referer($) {
    my $self = shift;
    my($url) = @_;
    $self->default_header(referer => lib::XCoro::gethost($url));
    # $self->default_header(referer => $url);
    return;
}

sub cookie($) {
    my $self = shift;
    my($cookie) = @_;
    $self->default_header(cookie => $cookie);
    return;
}

return 1;
