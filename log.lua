local http = require("resty.http")
local cjson = require("cjson.safe")
local tools = require("tools")
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


local data,err = cjson.encode(ngx.ctx.waf_log)
if not data then
	ngx.log(ngx.ERR,data)
	return
end

local function put_log(premature,data)
	local httpc = http.new()
	httpc:set_timeout(500)
	httpc:connect("127.0.0.1",5600)
	local res,err=httpc:request({
		method="post",
		path="/json/log",
		headers={
			["Content-Type"]="application/json"
		},
		body=data,
	})
	if not res then
		ngx.log(ERR,err)
	end

end

ngx.timer.at(0,put_log,data)

