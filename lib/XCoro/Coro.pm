package lib::XCoro::Coro;

use 5.10.0;

use strict;
use warnings;

no warnings 'experimental';


use base "Exporter";
our @EXPORT = qw/sleep/;

use Time::HiRes qw/time/;
use Params::Check qw/check/;

use Coro;
use Coro::LWP;
use Coro::AnyEvent; #*sleep = \&Coro::AnyEvent::sleep;

use lib::XCoro;
use lib::XCoro::Object;
use lib::XCoro::Coro::Watcher;
use lib::XCoro::Coro::Pool;

our $id = 1;

sub CONSTRUCT {
    my $self = shift;
    #----------------------------------------
    Carp::croak "" unless check({
        id    => {},
        desc  => {},
        debug => {},
        start_message => {},
        end_message => {},
        timelimit => {},
        semaphore => {},
        parent => {},
        param => {},
        function  => { defined => 1 },
    }, $self, 1);
    #----------------------------------------
    $self->{id}   //= $id++;
    $self->{desc} //= "";
    $self->{coro}->{desc} = $self->{desc};
    #----------------------------------------
    $self->{coro} = new Coro(sub {
        my $coro = $Coro::current;
        $self->{semaphore}->down if $self->{semaphore};
        $coro->{timeout_at} = time + $self->{timelimit} if $self->{timelimit};
        #----------------------------------------
        $coro->on_destroy(sub {
            $self->{semaphore}->up if $self->{semaphore};
            my($ret) = @_;
            $ret //= 0;
            
            if($self->{debug}) {
                $self->{end_message} = "" if(!defined($self->{end_message}));
                given(ref($ret))
                {
                    when(/HTTP::Response/i) {
                        ProcessResultElement($self->{end_message}, '[' . $ret->request->method . '] ' . $ret->request->uri, $ret->code);
                    }
                    
                    when(/HTTP::Request/i) {
                        ProcessResultElement($self->{end_message}, $ret->method, $ret->uri);
                    }
                    
                    when(/Webscan::Url/i) {
                        ProcessResultElement($self->{end_message} . '[' . $ret->{method} . '] ' . $ret->{uri}, '[' . $ret->{response_code} . ']');
                    }
                    
                    when(/Webscan::Test/i) {
                        ProcessResultElement("Test #" . $ret->{id}, $self->{end_message} . ' ' . $ret->{text}, $ret->{base_url});
                        print "\t";
                        ProcessResultElement("Test #" . $ret->{id}, "Vector : " . $ret->{attack_vector} . ' | ' ."Item : " . $ret->{attack_item} . ' | ' . "Payload : ", $ret->{payload});
                        print "\t";
                        ProcessResultElement("Test #" . $ret->{id}, "Code : " . $ret->{response}->code . ' | ' . "Time : " . $ret->{response_time} . ' | ' . "Size : " . $ret->{response_size});
                    }
                    
                    default {
                        print "Thread #$$self{id} ($$self{desc}) canceled: $ret\n";
                    }
                }
            }
            
            return $ret;
        });
        #----------------------------------------
        if($self->{debug}) {
            if(defined($self->{start_message}) && $self->{start_message}) {
                print $self->{start_message} . "\n\n";
            }
        }
        my $function = $self->{function};
        
        return $self->{parent}->$function(delete $self->{param});
    });
    #----------------------------------------
}

# <- int
sub start {
    return $_[0]->{coro}->ready;
}

# <- any
sub join  {
    return $_[0]->{coro}->join;
}

return 1;
