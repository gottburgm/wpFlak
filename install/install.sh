#!/bin/sh

echo "[ ✠ ✠ ✠ ] Installing Perl Dependencies ..."

cpan5 -f -T -i AnyEvent::HTTP::LWP::UserAgent
cpan5 -f -T -i Time::HiRes
cpan5 -f -T -i Term::ANSIColor
cpan5 -f -T -i Data::Dump
cpan5 -f -T -i URI::URL
cpan5 -f -T -i Parallel::ForkManager
cpan5 -f -T -i DateTime
cpan5 -f -T -i LWP::UserAgent
cpan5 -f -T -i LWP::ConnCache
cpan5 -f -T -i HTTP::Request
cpan5 -f -T -i HTTP::Response
cpan5 -f -T -i HTTP::Cookies
cpan5 -f -T -i Socket
cpan5 -f -T -i Coro
cpan5 -f -T -i Coro::State
cpan5 -f -T -i Coro::Semaphore
cpan5 -f -T -i Coro::AnyEvent
cpan5 -f -T -i Coro::LWP
cpan5 -f -T -i AnyEvent
cpan5 -f -T -i Carp
cpan5 -f -T -i Time::HiRes
cpan5 -f -T -i Params::Check
cpan5 -f -T -i LWP::Protocol::http
