package lib::XCoro::Coro::Watcher;

use 5.10.0;

use strict;
use warnings;

no warnings 'experimental';
use Carp;

use Time::HiRes qw/time/;
use Params::Check qw/check/;

use Coro::State;
use AnyEvent;

use lib::XCoro::Object;

sub CONSTRUCT {
    my $self = shift;
    #----------------------------------------
    Carp::croak "" unless check({
        interval => {},
        desc     => {},
    }, $self, 1);
    #----------------------------------------
    $self->{interval} ||= 1;
    #----------------------------------------
    $self->{timer} = AnyEvent->timer(
        interval => $self->{interval},
        cb => \&_cb,
    );
}

sub _cb {
    my $time = time;
    for my $coro (grep { ($_->{desc} && $_->{desc} !~ /^\[/) || !$_->{desc} } Coro::State::list) {
        if($coro->{timeout_at} && $time >= $coro->{timeout_at}) {
            $coro->cancel(0);
        }
    }
}

return 1;
