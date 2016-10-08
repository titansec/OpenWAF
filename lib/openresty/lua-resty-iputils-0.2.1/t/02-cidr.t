use Test::Nginx::Socket;
use Cwd qw(cwd);

plan tests => repeat_each() * 18;

my $pwd = cwd();

$ENV{TEST_LEDGE_REDIS_DATABASE} ||= 1;

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
};

no_long_string();
run_tests();

__DATA__
=== TEST 1: parse_cidr returns lower and upper bounds of network
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10.0/24")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
168430080
168430335

=== TEST 2: cidr with last octet in middle of range
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10.123/24")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
168430080
168430335

=== TEST 3: cidr with no prefix, assume /32
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10.123")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
168430203
168430203

=== TEST 4: cidr in bad form returns error message
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10.300/24")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
nil
Invalid octet: 300

=== TEST 4a: cidr in bad form returns error message
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10/24")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
nil
Invalid IP

=== TEST 4b: cidr in bad form returns error message
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local lower, upper = iputils.parse_cidr("10.10.10.0/99")
            ngx.say(lower)
            ngx.say(upper)
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
nil
Invalid prefix: /99
