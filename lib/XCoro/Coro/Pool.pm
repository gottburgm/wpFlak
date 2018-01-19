package lib::XCoro::Coro::Pool;

use 5.10.0;

use strict;
use warnings;

no warnings 'experimental';
use Carp;

use Params::Check qw/check/;

use lib::XCoro::Object;
use lib::XCoro::Coro;


sub CONSTRUCT {
    my $self = shift;
    
    #----------------------------------------
    Carp::croak "" unless check({
        desc  => {},
        debug => {},
        start_message => {},
        end_message => {},
        limit => {},
        timelimit => {},
        semaphore => {},
        parent => {},
        params => {},
        function  => { defined => 1 },
    }, $self, 1);
    #----------------------------------------
    $self->{debug} //= 0;
    $self->{desc} //= "";
    $self->{start_message} //= "";
    $self->{end_message} //= "";
    #----------------------------------------
    $self->{semaphore} = new Coro::Semaphore($self->{limit}) if($self->{limit});
    #----------------------------------------
    $self->{threads} = [map {
        new lib::XCoro::Coro(
            desc  => $self->{desc},
            debug => $self->{debug},
            start_message => $self->{start_message},
            end_message => $self->{end_message},
            timelimit => $self->{timelimit},
            semaphore => $self->{semaphore},
            parent => $self->{parent},
            param => $_,
            function  => $self->{function},
        );
    } @{ $self->{params} }];
    undef $self->{params};
    #----------------------------------------
}

# <- (int)
sub start_all {
    my $self = shift;
    return map { $_->{coro}->ready } @{ $self->{threads} };
}

# <- (any)
sub join_all {
    my $self = shift;
    return map { $_->{coro}->join } @{ $self->{threads} };
}

return 1;
