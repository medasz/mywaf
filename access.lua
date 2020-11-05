--修改响应头字段Server
ngx.header["Server"] = "mywaf"

--waf匹配流程
function waf_main()
	if white_ip_check() then

	elseif black_ip_check() then

	elseif black_user_agent_check() then

	elseif cc_deny() then

	elseif black_cookie_check() then

	elseif white_uri_check() then

	elseif black_uri_check() then

	elseif black_get_args_check() then

	else
		return
	end
end


waf_main()