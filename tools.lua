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
	if rules_dir_table then
		return
	end
	for filename,filedir in pairs(rules_dir_table) do
		local file_hanle = io.open(filedir,"r")
		if not file then
			return
		end
		local rules = file_handle:read('*a')
		file_handle:close()
		if rules and rules ~= "" then
			rules = cjson.decode(rules)
		end
		
		if rules then
			local t = {}
			for _,v in ipairs(rules) do
				table.insert(t,v['RuleItem'])
			end
			_M.rule_tables[filename] = t
			mgx.log(mgx.INFO,string.format("rule_tables[%s]:%s",filename,cjson.encode(t)))
		end
	end 
	return _M.rule_tables
end

return _M