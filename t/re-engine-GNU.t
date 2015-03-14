# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl re-engine-GNU.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 17;
BEGIN { use_ok('re::engine::GNU') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
use re::engine::GNU -debug => ($ENV{AUTHOR_TEST} || 0);
ok (0x00be0cd == $re::engine::GNU::RE_SYNTAX_AWK, 'RE_SYNTAX_AWK');
ok (0x10102c6 == $re::engine::GNU::RE_SYNTAX_ED, 'RE_SYNTAX_ED');
ok (0x000a91c == $re::engine::GNU::RE_SYNTAX_EGREP, 'RE_SYNTAX_EGREP');
ok (0x0000000 == $re::engine::GNU::RE_SYNTAX_EMACS, 'RE_SYNTAX_EMACS');
ok (0x023b24d == $re::engine::GNU::RE_SYNTAX_GNU_AWK, 'RE_SYNTAX_GNU_AWK');
ok (0x0000b06 == $re::engine::GNU::RE_SYNTAX_GREP, 'RE_SYNTAX_GREP');
ok (0x02bb2fd == $re::engine::GNU::RE_SYNTAX_POSIX_AWK, 'RE_SYNTAX_POSIX_AWK');
ok (0x10102c6 == $re::engine::GNU::RE_SYNTAX_POSIX_BASIC, 'RE_SYNTAX_POSIX_BASIC');
ok (0x020bb1c == $re::engine::GNU::RE_SYNTAX_POSIX_EGREP, 'RE_SYNTAX_POSIX_EGREP');
ok (0x003b2fc == $re::engine::GNU::RE_SYNTAX_POSIX_EXTENDED, 'RE_SYNTAX_POSIX_EXTENDED');
ok (0x00106c4 == $re::engine::GNU::RE_SYNTAX_POSIX_MINIMAL_BASIC, 'RE_SYNTAX_POSIX_MINIMAL_BASIC');
ok (0x003f2ec == $re::engine::GNU::RE_SYNTAX_POSIX_MINIMAL_EXTENDED, 'RE_SYNTAX_POSIX_MINIMAL_EXTENDED');
ok (0x10102c6 == $re::engine::GNU::RE_SYNTAX_SED, 'RE_SYNTAX_SED');
ok ('test' =~ /\(tes\)t/, "'test' =~ /\(tes\)t/");
ok ('test' =~ [ 0, '\(tes\)t' ], "'test' =~ [ 0, '\(tes\)t' ]");
ok ('test' =~ { syntax => 0, pattern => '\(tes\)t' }, "'test' =~ { syntax => 0, pattern => '\(tes\)t' }");
