#!/bin/bash

echo "[ ✠ ✠ ✠ ] Installing Perlbrew ..."
\wget -O - https://install.perlbrew.pl | bash

echo "[ ✠ ✠ ✠ ] Installing Perl 5.18.0 ..."
perlbrew init
perlbrew -n -f install 5.18.0
perlbrew use perl-5.18.0

sudo mv /bin/perl5 /bin/perl5.24
sudo mv /bin/cpan5 /bin/cpan5.24
sudo ln -s ~/perl5/perlbrew/perls/perl-5.18.0/bin/perl /bin/perl5
sudo ln -s ~/perl5/perlbrew/perls/perl-5.18.0/bin/cpan /bin/cpan5
