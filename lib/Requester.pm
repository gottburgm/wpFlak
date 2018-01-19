package lib::Requester;

use 5.10.0;

use strict;
use warnings;

use LWP::UserAgent;
use HTTP::Cookies;
use Data::Dump qw(dump);

no warnings 'experimental';

BEGIN {

    use lib::XCoro::Coro::Pool;
    use lib::XCoro::Coro::Watcher;
    use IO::Socket::SSL;
    
    # Remove  SSL Checks
    
    $ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;
    
    $ENV{HTTPS_DEBUG} = 1;
    
    IO::Socket::SSL::set_ctx_defaults(
        SSL_verifycn_scheme => 'www',
        SSL_verify_mode => 0,
    );
    
}

sub new {
    my $type  = shift;
    my $class = ref $type || $type;
    my $self  = bless {
       browser => 0,
    }, $class;
    
    bless $self, $class;
    
    $self->_initialize();
    
    return $self;
}

### Attributes

sub browser {
    my ( $self ) = @_;
    
    return $self->{browser};
}


### Methods

sub _initialize {
    my ( $self ) = @_;
    my $browser = LWP::UserAgent->new();
    
    my $cookie_jar = HTTP::Cookies->new(
        file     => "/tmp/cookies.lwp",
        autosave => 1,
    );
    
    $browser->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801");
    $browser->timeout(10);
    $browser->protocols_allowed([qw( ftp ftps http https )]);
    
    $self->{browser} = $browser;
}

sub processRequest {
    my ( $self, $request) = @_;

    return $self->{browser}->request($request);
}

sub getIP {
    my ( $self ) = @_;
    my $ip = '';
    my $response = '';
    my $page_source = '';
    
    my @matches = ();
    
    $response = $self->{browser}->get("http://monip.org/");
    if($response) {
        $page_source = $response->content;
        @matches = $page_source =~ /IP\s*:\s*(.*?)</sgi;
        $ip = $matches[0] if($matches[0]);
    } else {
        print color("bold red"), "[ERROR] Could Not Get Your IP Address .\n";
        exit;
    }
    
    return $ip;
}

return 1;
