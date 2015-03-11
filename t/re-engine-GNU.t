# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl re-engine-GNU.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 4;
BEGIN { use_ok('re::engine::GNU') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
use re::engine::GNU -debug => ($ENV{AUTHOR_TEST} || 0);
ok ('test' =~ /\(tes\)t/, "'test' =~ /\(tes\)t/");
ok ('test' =~ [ 0, '\(tes\)t' ], "'test' =~ [ 0, '\(tes\)t' ]");
ok ('test' =~ { syntax => 0, pattern => '\(tes\)t' }, "'test' =~ { syntax => 0, pattern => '\(tes\)t' }");
