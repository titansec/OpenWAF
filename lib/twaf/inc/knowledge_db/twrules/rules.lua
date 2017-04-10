local _M = {}

_M.rules = {
{
    id = "300002",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase = "access",
    action = "deny",
    meta = 403,
    severity = "high",
    rule_name = "malicious.trojan.general",
    desc = "检测访问木马页面，检查请求头名称中含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var = "REQUEST_HEADERS_NAMES"
                }
            },
            transform = "lowercase",
            operator = "regex",
            pattern = "x_(?:key|file)\b"
        }
    }
},
{
    id = "300003",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase = "access",
    action = "deny",
    meta = 403,
    severity = "high",
    rule_name = "malicious.trojan.general.a",
    desc = "检测木马访问，检查请求文件名中是否含有关键字",
    match = {
        {
            vars = {
                {
                    var = "REQUEST_FILENAME"
                }
            },
            transform = {
                "uri_decode_uni", 
                "html_decode", 
                "lowercase"
            },
            operator = "contains",
            pattern = "root%.exe"
        }
    }
},
{
    id = "300004",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase = "access",
    action = "deny",
    meta = 403,
    severity = "critical",
    rule_name = "malicious.webshell",
    desc = "检测向常见静态资源文件发出的HTTP POST请求",
    match = {
        {
            vars = {
                {
                    var = "REQUEST_METHOD"
                }
            },
            operator = "equal",
            pattern = "POST"
        },
        {
            vars = {
                {
                    var = "REQUEST_BASENAME"
                }
            },
            operator = "regex",
            pattern = "(?i)\\.(gif|jpe?g|png|bmp|js|css|txt|exe|docx?|xlsx?|pptx?|zip|rar|7z)[\\.\\s]*$"
        }
    }
},
{
    id = "300005",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase = "header_filter",
    action = "deny",
    meta = 403,
    severity = "critical",
    rule_name = "malicious.webshell.a",
    desc = "检测向常图片格式文件请求但返回text类型的请求",
    match = {
        {
            vars = {
                {
                    var = "REQUEST_FILENAME"
                }
            },
            operator = "regex",
            pattern = "(?i)\\.(gif|jpe?g|png|bmp)[\\.\\s]*$"
        },
        {
            vars = {
                {
                    var = "RESPONSE_HEADERS",
                    parse = {
                        specific = "Content-Type"
                    }
                }
            },
            transform = "lowercase",
            operator = "begins_with",
            pattern = "text/"
        },
        {
            vars = {
                {
                    var = "RESPONSE_STATUS"
                }
            },
            operator = "less",
            pattern = 400
        }
    }
},
{
    id = "300006",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase = "access",
    action = "deny",
    meta = 403,
    severity = "critical",
    rule_name = "malicious.webshell.b",
    desc = "检测对设备文件名的请求",
    match = {
        {
            vars = {
                {
                    var = "REQUEST_BASENAME"
                }
            },
            operator = "regex",
            pattern = "(?i)^(?:aux|con|nul|prn|com\\d|lpt\\d).*\\.(?:asa|cer|aspx?|asax|ascx|ashx|asmx)"
        }
    }
},
{
    id = "700001",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.crawler.general",
    desc  = "检测网站爬取工具，检查User-Agent请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            transform = "lowercase",
            operator = "regex",
            pattern  = "(?:e(?:mail(?:(?:collec|harves|magne)t|(?: extracto|reape)r|siphon|wolf)|(?:collecto|irgrabbe)r|xtractorpro|o browse)|m(?:ozilla\\/4\\.0 \\(compatible; advanced email extractor|ailto:craftbot\\@yahoo\\.com)|a(?:t(?:tache|hens)|utoemailspider|dsarobot)|w(?:eb(?:emailextrac| by mail)|3mir)|f(?:astlwspider|loodgate)|p(?:cbrowser|ackrat|surf)|(?:digout4uagen|takeou)t|\\bdatacha0s\\b|hhjhj@yahoo|chinaclaw|rsync|shai|zeus)"
        }
    }
},
{
    id = "700002",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.crawler.general.a",
    desc  = "检测网站爬取工具，检查User-Agent请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "regex",
            pattern  = "(?:\\b(?:(?:indy librar|snoop)y|microsoft url control|lynx)\\b|mozilla\\/2\\.0 \\(compatible; newt activex; win32\\)|w(?:3mirror|get)|download demon|l(?:ibwww|wp)|p(?:avuk|erl)|big brother|autohttp|netants|eCatch|curl)"
        }
    }
},
{
    id = "700003",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.crawler.general.b",
    desc  = "检测网站爬取工具，检查User-Agent请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "regex",
            pattern  = "Mozilla/5\\.0 \\(compatible; en-US; Gnomit\\) Gnomit/|goso_crawler/|Dom2Dom/"
        }
    }
},
{
    id = "700004",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.appscan",
    desc  = "检测网站扫描工具，检查请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept"
                    }
                }
            },
            operator = "equal",
            pattern  = "*/*"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept-Language"
                    }
                }
            },
            operator = "equal",
            pattern  = "en-US"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "equal",
            pattern  = "Mozilla/4%.0 %(compatible; MSIE 6%.0; Win32%)"
        }
    }
},
{
    id = "700006",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.general.a",
    desc  = "检测网站扫描工具，检查User-Agent的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "regex",
            pattern  = "(?i)\\b(?:a(?:bsinthe|rachni|dvanced email extractor|utogetcontent)|b(?:ilbo|lack ?widow|rutus|sqlbf)|cgichk|cisco-torch|core-project|crimscanner|datacha0s|dav\\.pm/v|dirbuster|domino hunter|dotdotpwn|email extractor|fhscan core|floodgate|get-minimal|gootkit auto-rooter scanner|gr(?:abber|endel-scan)|h(?:avij|ydra)|inspath \\[path disclosure finder|internet ninja|jaascois|m(?:etis|orfeus fucking scanner|ozilla/(?:4\\.0 \\(compatible(?:; msie 6\\.0; win32)?\\)|5\\.0 sf/)|ysqloit)|n(?:-stealth|e(?:ssus|tsparker)|ikto)|n(?:map(?:[- ]nse| scripting engine)|sauditor)|openvas|p(?:a(?:ngolin|ros)|mafind|rog\\.customcrawler|rowebwalker|ymills-spider|ython-httplib2)|qualys was|sql(?: power injector|map|ninja)|s\\.t\\.a\\.l\\.k\\.e\\.r\\.|security scan|springenwerk|teh forest lobster|this is an exploit|toata dragostea|uil2pn|user-agent:|vega/|voideye|w(?:3af|eb(?:bandit|inspect|shag|trends security analyzer|vulnscan))|whatweb|whcc|wordpress(?: hash grabber|/\\d+\\.)|xmlrpc exploit|zmeu\\b)|\\.nasl"
        }
    }
},
{
    id = "700007",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.general.b",
    desc  = "检测网站扫描工具，检查User-Agent的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "regex",
            pattern  = "(?:Mozilla|MSIE|TencentTraveler|Internet Explorer)(?:[/ ]\\d\\.\\d)?$"
        }
    }
},
{
    id = "700008",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta   = 403,
    severity = "medium",
    rule_name = "auto.scanner.nessus",
    desc  = "检测网站扫描工具，检查User-Agent的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_FILENAME"
                }
            },
            transform = "lowercase",
            operator = "contains",
            pattern  = {
                "nessustest",
                "appscan_fingerprint"
            }
        }
    }
},
{
    id = "700009",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "high",
    rule_name = "auto.scanner.wvs",
    desc  = "检测网站扫描工具，检查请求头的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS_NAMES"
                },
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept"
                    }
                }
            },
            transform = "lowercase",
            operator = "contains",
            pattern  = "acunetix"
        }
    }
},
{
    id = "700010",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.general.c",
    desc  = "检测网站扫描工具，检查User-Agent的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            transform = "lowercase",
            operator = "regex",
            pattern  = "(?:whitehat\\.ro|scanner)$"
        }
    }
},
{
    id = "700011",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.crawler.general.c",
    desc  = "检测网站扫描工具，检查User-Agent的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "contains",
            pattern  = "larbin"
        }
    }
},
{
    id = "700012",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.wvs.a",
    desc  = "检测网站扫描工具，检查请求头的值含有关键字的HTTP请求",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_URI"
                }
            },
            transform = "lowercase",
            operator = "contains",
            pattern  = "acunetix_wvs_security_test"
        }
    }
},
{
    id = "700014",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.appscan.a",
    desc  = "检测网站扫描工具，检查请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept-Language"
                    }
                }
            },
            operator = "contains",
            pattern  = "en%-US"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept"
                    }
                }
            },
            operator = "contains",
            pattern  = "text/html,application/xhtml\\%+xml,application/xml;q=0.9,%*/%*;q=0%.8"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "regex",
            pattern  = "Mozilla/5\\.0\\s\\(compatible;\\sMSIE\\s10\\.0;\\sWindows\\sNT\\s6\\.1;\\sTrident/7\\.0\\)|Mozilla/4\\.0\\s\\(compatible;\\sMSIE\\s8\\.0;\\sWindows\\sNT\\s6\\.1;\\sWin64;\\sx64;\\sTrident/4\\.0;\\s\\.NET\\sCLR\\s2\\.0\\.50727;\\sSLCC2;\\s\\.NET\\sCLR\\s3\\.5\\.30729;\\s\\.NET\\sCLR\\s3\\.0\\.30729;\\sMedia\\sCenter\\sPC\\s6\\.0;\\sTablet\\sPC\\s2\\.0\\)"
        }
    }
},
{
    id = "700015",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.appscan.b",
    desc  = "检测网站扫描工具，检查请求头的值是否含有关键字",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept-Language"
                    }
                }
            },
            operator = "contains",
            pattern  = "zh%-CN"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "Accept"
                    }
                }
            },
            operator = "equal",
            pattern  = "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*"
        },
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS",
                    parse = {
                        specific = "User-Agent"
                    }
                }
            },
            operator = "equal",
            pattern  = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/7.0)"
        }
    }
},
{
    id = "700017",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.general.e",
    desc  = "检测网站扫描工具，检查请求头及请求头的值",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_HEADERS"
                },
                {
                    var   = "REQUEST_HEADERS_NAMES"
                }
            },
            operator = "regex",
            pattern  = "(?i)myvar=1234|x-ratproxy-loop|bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10,5-11,5-12,5-13,5-14"
        }
    }
},
{
    id = "700018",
    release_version = "858",
    charactor_version = "001",
    opts = {
        nolog = false
    },
    phase    = "access",
    action   = "deny",
    meta     = 403,
    severity = "medium",
    rule_name = "auto.scanner.general.f",
    desc  = "检测网站扫描工具，检查请求URI",
    match = {
        {
            vars = {
                {
                    var   = "REQUEST_FILENAME"
                }
            },
            operator = "regex",
            pattern  = "(?i)/(?:\\.adsensepostnottherenonobook|<invalid>hello\\.html|actsensepostnottherenonotive|acunetix-wvs-test-for-some-inexistent-file|antidisestablishmentarianism|appscan_fingerprint/mac_address|arachni-|cybercop|nessus(?:_is_probing_you_|test)|netsparker-|rfiinc\\.txt|thereisnowaythat-you-canbethere|w3af/remotefileinclude\\.html)|appscan_fingerprint"
        }
    }
}
}

return _M
