use Test::Nginx::Socket;
use Cwd qw(cwd);

plan tests => repeat_each() * 27;

my $pwd = cwd();

$ENV{TEST_LEDGE_REDIS_DATABASE} ||= 1;

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
};

no_long_string();
run_tests();

__DATA__
=== TEST 1: parse_cidrs array of lower/upper arrays
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.11.0/24",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)
            if not parsed then
                ngx.say(err)
            else
                for _, net in ipairs(parsed) do
                    ngx.say(net[1], " ", net[2])
                end
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
168430080 168430335
168430336 168430591
168430593 168430593

=== TEST 2: invalid CIDR logs error and are ignored
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.20.0/40",
                "10.10.11.0/24",
                "300.0.0.0",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)
            if not parsed then
                ngx.say(err)
            else
                for _, net in ipairs(parsed) do
                    ngx.say(net[1], " ", net[2])
                end
            end
        ';
    }
--- request
GET /a
--- error_log
Error parsing '10.10.20.0/40': Invalid prefix: /40
--- response_body
168430080 168430335
168430336 168430591
168430593 168430593

=== TEST 2a: invalid CIDR logs error and are ignored
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.11.0/24",
                "300.0.0.0",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)
            if not parsed then
                ngx.say(err)
            else
                for _, net in ipairs(parsed) do
                    ngx.say(net[1], " ", net[2])
                end
            end
        ';
    }
--- request
GET /a
--- error_log
Error parsing '300.0.0.0': Invalid octet: 300
--- response_body
168430080 168430335
168430336 168430591
168430593 168430593

=== TEST 3: ip_in_cidrs checks ip exists in array of parsed cidrs
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.11.0/24",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.ip_in_cidrs("10.10.10.123", parsed)
            if pass == true then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
OK

=== TEST 3b: ip_in_cidrs checks ip exists in array of parsed cidrs, /32 matches
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.11.0/24",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.ip_in_cidrs("10.10.12.1", parsed)
            if pass == true then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
OK

=== TEST 4a: invalid ip to ip_in_cidrs returns error
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "10.10.10.0/24",
                "10.10.11.0/24",
                "10.10.12.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.ip_in_cidrs("10.10.12.400", parsed)
            if pass == true then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
Invalid octet: 400

=== TEST 5: binip_in_cidrs checks ip exists in array of parsed cidrs
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "127.0.0.0/24"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.binip_in_cidrs(ngx.var.binary_remote_addr, parsed)
            if pass == true then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
OK

=== TEST 5a: binip_in_cidrs checks ip not exists in array of parsed cidrs
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "128.0.0.0/24"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.binip_in_cidrs(ngx.var.binary_remote_addr, parsed)
            if pass == false then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
OK

=== TEST 5b: binip_in_cidrs checks ip exists in array of parsed cidrs
--- http_config eval
"$::HttpConfig"
. q{
}
--- config
    location /a {
        content_by_lua '
            local iputils = require("resty.iputils")
            local cidrs = {
                "128.0.0.0/24",
                "127.0.0.1"
            }
            local parsed, err = iputils.parse_cidrs(cidrs)

            local pass, err = iputils.binip_in_cidrs(ngx.var.binary_remote_addr, parsed)
            if pass == true then
                ngx.say("OK")
            elseif err then
                ngx.say(err)
            else
                ngx.say("FAIL")
            end
        ';
    }
--- request
GET /a
--- no_error_log
[error]
--- response_body
OK

