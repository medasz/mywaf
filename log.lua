local http = require("resty.http")
local cjson = require("cjson.safe")
local tools = require("tools")
local mysql = require('resty.mysql')
-- 加载uuid库
local uuid = require("resty.jit-uuid")
if not ngx.ctx.waf_log then
	ngx.ctx.waf_log={}
	ngx.ctx.waf_log["attack_type"]="general"
	ngx.ctx.waf_log["rule"]="-"
	ngx.ctx.waf_log["data"]="-"
end
ngx.ctx.waf_log["client_ip"] = tools.get_client_ip()
ngx.ctx.waf_log["local_time"] = ngx.localtime()
ngx.ctx.waf_log["server_name"] = ngx.var.server_name
ngx.ctx.waf_log["req_uri"] = ngx.var.request_uri
ngx.ctx.waf_log["user_agent"] = ngx.var.http_user_agent
ngx.ctx.waf_log["host"] = ngx.var.host


-- local data,err = cjson.encode(ngx.ctx.waf_log)
-- if not data then
-- 	ngx.log(ngx.ERR,data)
-- 	return
-- end

-- local function put_log(premature,data)
-- 	local httpc = http.new()
-- 	httpc:set_timeout(500)
-- 	httpc:connect("127.0.0.1",5600)
-- 	local res,err=httpc:request({
-- 		method="post",
-- 		path="/json/log",
-- 		headers={
-- 			["Content-Type"]="application/json"
-- 		},
-- 		body=data,
-- 	})
-- 	if not res then
-- 		ngx.log(ERR,err)
-- 	end

-- end


local function put_log(premature,data)
    local db,err = mysql:new()
    if err then
        ngx.log(ngx.ERR,err)
        return
    end
    db:set_timeout(1000)
    local options={
        host="127.0.0.1",
        port=3306,
        database="mywaf",
        user="admin",
        password="password",
    }
    local ok,err=db:connect(options)
    if not ok then
        ngx.log(ngx.ERR,err)
        db:close()
        return
    end

    if data["attack_type"]=="cc_deny" and mywaf.get_config_cc_black_ip() == "on" then
        local sql="insert into rule (rule_item,rule_type)values('%s','black_ip')"
        local sql_res=string.format(sql,data["client_ip"])
        local res,err,errcode,sqlstate=db:query(sql_res)
        if not res then
            ngx.log(ngx.ERR,err)
        end




        sql="update flag set uuid='%s' where name = rule"
        sql_res=string.format(sql,uuid())
        res,err,errcode,sqlstate=db:query(sql_res)
        if not res then
            ngx.log(ngx.ERR,err)
        end
    end


    local insert_sql = "insert into waf_log(host,rule, client_ip, attack_type, data, server_name, user_agent, req_uri, local_time, local_time_obj) value ('%s',%s,'%s','%s',%s,'%s','%s',%s,'%s','%s')"
    local insert_res=string.format(insert_sql,data["host"],ngx.quote_sql_str(data["rule"]), data["client_ip"], data["attack_type"], ngx.quote_sql_str(data["data"]), data["server_name"], data["user_agent"], ngx.quote_sql_str(data["req_uri"]), data["local_time"], data["local_time"])
    local res,err,errcode,sqlstate=db:query(insert_res)
    if not res then
        ngx.log(ngx.ERR,err)
        db:close()
        return
    end
end
ngx.timer.at(0,put_log,ngx.ctx.waf_log)
