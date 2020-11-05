--修改响应头字段Server
ngx.header["Server"] = "mywaf"

--waf匹配流程
function waf_main()
	if white_ip_check() then

	elseif black_ip_check() then

	elseif black_user_agent_check() then

	elseif cc_deny() then

	else
		return
	end
end


waf_main()