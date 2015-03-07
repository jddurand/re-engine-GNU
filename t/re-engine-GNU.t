# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl re-engine-GNU.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 2;
BEGIN { use_ok('re::engine::GNU') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
use re::engine::GNU;
ok ('test' =~ [ 0, '\(tes\)t' ], "'test' =~ [ 0, '\(tes\)t' ]");
