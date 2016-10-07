
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

local twaf_func  = require "lib.twaf.inc.twaf_func"
local ssl        = require "ngx.ssl"
local ocsp       = require "ngx.ocsp"

local function _ssl(crt, key)

    local ok, err = ssl.clear_certs()
    if not ok then
        ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates")
        return ngx.exit(ngx.ERROR)
    end
    
            
    local f = assert(io.open(crt))
    local pem_cert_chain = f:read("*a")
    f:close()
            
    local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
    if not der_cert_chain then
        ngx.log(ngx.ERR, "failed to convert certificate chain from PEM to DER: ", err)
        return ngx.exit(ngx.ERROR)
    end
            
    local ok, err = ssl.set_der_cert(der_cert_chain)
    if not ok then
        ngx.log(ngx.ERR, "failed to set DER cert: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    local f = assert(io.open(key))
    local der_pkey = f:read("*a")
    f:close()
    
    der_pkey, err = ssl.priv_key_pem_to_der(der_pkey)
    if not der_pkey then
        ngx.log(ngx.ERR, "failed to convert pkey from PEM to DER: ", err)
        return ngx.exit(ngx.ERROR)
    end
            
    local ok, err = ssl.set_der_priv_key(der_pkey)
    if not ok then
        ngx.log(ngx.ERR, "failed to set DER private key: ", err)
        return ngx.exit(ngx.ERROR)
    end
end

local function _ocsp(path)

    local f = assert(io.open(path))
    local pem_cert_chain = f:read("*a")
    f:close()
    
    local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
    if not der_cert_chain then
        ngx.log(ngx.ERR, "failed to convert certificate chain from PEM to DER: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    local url, err = ocsp.get_ocsp_responder_from_der_chain(der_cert_chain)
    if not url then
        ngx.log(ngx.ERR, "failed to get OCSP responder: ", err)
        return
    end
end

function _M.ssl_cert(self, _twaf)

    local conf =  nil
    local cf   = _twaf.config.twaf_access_rule
    local dn   =  ssl.server_name()
    
    if not dn then
        return false
    end
    
    for _, rule in ipairs(cf.rules) do
        local ngx_ssl = twaf_func:state(rule.ngx_ssl)
        if ngx_ssl == true then
            local from, to, err = ngx.re.find(dn, rule["host"], "jo")
            if from then
                conf = rule
                break
            end
        end
    end
    
    if not conf then
        ngx.exit(404)
    end
    
    local client_ssl = twaf_func:state(conf.client_ssl)
    if client_ssl then
        _ocsp(conf.client_ssl_cert)
    end
    
    _ssl(conf.ngx_ssl_cert, conf.ngx_ssl_key)
end

return _M
