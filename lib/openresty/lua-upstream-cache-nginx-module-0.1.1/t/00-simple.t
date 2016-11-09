use Test::Nginx::Socket;

plan tests => repeat_each() * (blocks() * 2);

no_long_string();

run_tests();

__DATA__

=== TEST 1: example echo
--- config
    location = /test {
        content_by_lua '
            local example = require "nginx.example"
	    ngx.say(example.get_uri())
        ';
    }
--- request
GET /test
--- response_body
/test
