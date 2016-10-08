use Test::Nginx::Socket;
use Cwd qw(cwd);

plan tests => repeat_each() * 24;

my $pwd = cwd();

$ENV{TEST_LEDGE_REDIS_DATABASE} ||= 1;

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
};

no_long_string();
run_tests();

__DATA__
=== TEST 1: ip2bin returns binary representation of IP
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("127.0.0.1")
            ngx.say(bin_ip)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
2130706433

=== TEST 2: ip2bin returns binary representation of each octet
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("127.0.0.1")
            for _, octet in ipairs(bin_octets) do
                ngx.say(octet)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
127
0
0
1

=== TEST 3: ip2bin returns error on bad ip form - too few octets
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("127.0.1")
            if not bin_ip then
                ngx.say(bin_octets)
            else
                ngx.say(bin_ip)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
Invalid IP


=== TEST 3a: ip2bin returns error on bad ip form
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin(12344567)
            if not bin_ip then
                ngx.say(bin_octets)
            else
                ngx.say(bin_ip)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
IP must be a string

=== TEST 3b: ip2bin returns error on bad ip form - octet out of bounds
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("100.256.900.0")
            if not bin_ip then
                ngx.say(bin_octets)
            else
                ngx.say(bin_ip)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
Invalid octet: 256

=== TEST 3c: ip2bin returns error on bad ip form - string octet
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("127.0.asdf.1")
            if not bin_ip then
                ngx.say(bin_octets)
            else
                ngx.say(bin_ip)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
Invalid octet: asdf

=== TEST 3d: ip2bin returns error on bad ip form - too many octets
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local bin_ip, bin_octets = iputils.ip2bin("127.0.0.0.1")
            if not bin_ip then
                ngx.say(bin_octets)
            else
                ngx.say(bin_ip)
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
Invalid IP

=== TEST 4: ip2bin returns binary representation of IP with lrucache
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            iputils.enable_lrucache(100)

            local bin_ip, bin_octets = iputils.ip2bin("127.0.0.1")
            ngx.say(bin_ip)
            local bin_ip, bin_octets = iputils.ip2bin("127.0.0.1")
            ngx.say(bin_ip)

            local bin_ip, bin_octets = iputils.ip2bin("10.0.0.1")
            ngx.say(bin_ip)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
2130706433
2130706433
167772161
