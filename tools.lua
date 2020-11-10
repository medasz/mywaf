local cjson = require("cjson.safe")
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
		"black_post.rule"
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
		ngx.log(ngx.INFO,rules)
		file_handle:close()
		if rules and rules ~= "" then
			rules = cjson.decode(rules)
		end
		
		if rules then:
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
end

return _M