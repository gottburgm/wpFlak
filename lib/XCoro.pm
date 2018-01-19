package lib::XCoro;

use 5.10.0;

use strict;
use warnings;

no warnings 'experimental';

use Carp;

use base "Exporter";

our @EXPORT = qw( prompt print_dump setscheme gethost );

our @EXPORT_OK = @EXPORT;

sub prompt
{
   my($msg) = @_;
   print $msg;
   return scalar readline;
}

sub print_dump(@)
{
   require Data::Dump;
   say Data::Dump::dump(@_);
   return;
}

sub setscheme($;$)
{
   Carp::croak unless @_;
   my($url, $scheme) = @_;
   $scheme ||= "http";
   return $url =~ m~^\w+://~ ? $url : "$scheme://$url";
}

sub gethost($)
{
   Carp::croak unless @_;
   my($url) = @_;
   my($host) = $url =~ m~^((?:\w+://)?[^/]+)~;
   return $host . '/';
}

2;

