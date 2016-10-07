local _M = {}

_M.rules = {
{
    weight = 0,
    id = "200001",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false,
        sanitise_arg = {
            "password", 
            "passwd"
        }
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "critical",
    category = "5rOo5YWl5pS75Ye7",
    charactor_name = "YXR0YWNrLmluamVjdGlvbi5zcWwubGliaW5qZWN0aW9u",
    desc  = "sqli检测",
    match = {{
        vars = {{
            var = "REQUEST_FILENAME"
        },{
            var = "ARGS_NAMES"
        },{
            var = "ARGS",
            parse = {
                ignore = {
                    "_test"
                }
            }
        }},
        transform = "uri_decode_uni",
        operator = "detect_sqli"
    }}
},
{
    weight = 0,
    id = "200002",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false,
        sanitise_arg = {
            "password", 
            "passwd"
        }
    },
    phase    = "access",
    action   = "deny",
    meta   = 403,
    severity = "high",
    category = "6Leo56uZ5pS75Ye7",
    charactor_name = "YXR0YWNrLnhzcy5saWJpbmplY3Rpb24=",
    desc  = "xss检测",
    match = {{
        vars = {{
            var = "REQUEST_METHOD"
        }},
        operator = "equal",
        pattern = "GET"
    },
    {
        vars = {{
            var = "REQUEST_FILENAME"
        },{
            var = "ARGS_NAMES"
        },{
            var = "ARGS",
            parse = {
                ignore = {
                    "_test"
                }
            }
        }},
        transform = "html_decode",
        operator = "detect_xss"
    }}
},
}

return _M
