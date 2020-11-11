local cjson = require("cjson.safe")
local config = require("config")
local _M = {
	version = "1.0",
	rule_tables = {},
	rule_files = {
		"white_ip.rule",
		"black_ip.rule",
		"black_user_agent.rule",
		"white_uri.rule",
		"black_uri.rule",
		"black_cookie.rule",
		"black_get_args.rule",
		"black_post.rule",
		"black_file_ext.rule"
	}
}

-- 获取文件路径
function _M.get_rules_dir(rule_dir)
	local rules_dir_table = {}
	for _,filename in ipairs(_M.rule_files) do
		local file_dir = string.format("%s/%s",rule_dir,filename)
		rules_dir_table[filename] = file_dir
		ngx.log(ngx.INFO,string.format("rules_dir_table filename:%s file_dir:%s",filename,file_dir))
	end
	return rules_dir_table
end

-- 读取规则
function _M.get_rules(rule_dir)
	local rules_dir_table = _M.get_rules_dir(rule_dir)
	for filename,filedir in pairs(rules_dir_table) do
		local file_handle = io.open(filedir,"r")
		if not file_handle then
			return _M.rule_tables
		end
		local rules = file_handle:read('*a')
		file_handle:close()
		if rules then
			rules = cjson.decode(rules)
		end
		
		if rules then
			local t = {}
			for _,v in ipairs(rules) do
				table.insert(t,v['RuleItem'])
			end
			_M.rule_tables[filename] = t
			ngx.log(ngx.INFO,string.format("rule_tables[%s]:%s",filename,cjson.encode(t)))
		end
	end 
	return _M.rule_tables
end

-- 获取远程ip
function _M.get_client_ip()
	local client_ip = ngx.req.get_headers()['x_real_ip']
	if client_ip == nil then
		client_ip = ngx.req.get_headers()['x_forwarded_for']
	end
	if client_ip == nil then
		client_ip = ngx.var.remote_addr
	end
	if client_ip == nil then
		client_ip = ""
	end
	return client_ip
end

-- 日志记录
function _M.log_record(log_dir,attack_type,uri,data,rule)
	uri = ngx.unescape_uri(uri)
	local local_time = ngx.localtime()
	local client_ip = _M.get_client_ip()
	local server_name = ngx.var.server_name
	local user_agent = ngx.var.http_user_agent
	local log_json_obj = {
		client_ip = client_ip,
		local_time = local_time,
		attack_type = attack_type,
		server_name = server_name,
		req_uri = uri,
		user_agent = user_agent,
		data = data,
		rule = rule
	}
	local log_line = cjson.encode(log_json_obj)
	local log_file = log_dir.."/"..ngx.today().."_waf.log"
	local file,err = io.open(log_file,"a")
	if file == nil then
		ngx.log(ngx.INFO,string.format("open file err:%s",err))
		return
	end
	file:write(log_line.."\n")
	file:flush()
	file:close()
end

-- waf拦截界面
function _M.waf_output()
	if config.config_waf_mode == "redirect" then
		ngx.redirect(config.config_redirect_uri,301)
	else
		ngx.header['content-type']= "text/html"
		ngx.status = ngx.HTTP_FORBIDDEN
		ngx.say(string.format(config.config_output_html,_M.get_client_ip()))
		ngx.exit(ngx.status)
	end
end

-- 获取content-type中boundary值
-- Content-Type: multipart/form-data; boundary=---------------------------269914186631737613662904992226
function _M.get_boundary()
	local content_type = ngx.req.get_headers()['content_type']
	if content_type == nil then
		return
	end
	if type(content_type) == "table" then
		content_type = content_type[1]
	end
	local m = ngx.re.match(content_type,";\\s*boundary=([^\",;]+)","sjo")
	if m then
		return m
	end
	return ngx.re.match(content_type,";\\s*boundary=\"([^\"]+)\"","sjo")
end

-- 规则匹配
function _M.ruleMatch(data,rules)
	if rules then
		for _,rule in ipairs(rules) do
			if rule ~= "" and ngx.re.match(ngx.unescape_uri(data),rule,"sjo") then
				return true,rule
			end
		end
	end
	return false,nil
end

return _M