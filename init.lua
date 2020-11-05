require 'config'
require 'tools'

--white ip check
function white_ip_check()
	if config_white_ip_status == "on" then
		local client_ip 	= 	get_client_ip()
		local white_ip_rule	=	get_rule("white_ip.rule")
		if white_ip_rule ~= nil then
			for _,rule in ipairs(white_ip_rule) do
				if rule ~= "" and client_ip == rule then
					log_record("white ip",ngx.var.request_uri,client_ip,rule)
					return true
				end
			end
		end
	end
end

--black ip check
function black_ip_check()
	if config_black_ip_status == "on" then
		local client_ip = get_client_ip()
		local black_ip_rule = get_rule("black_ip.rule")
		if black_ip_rule ~= nil then
			for _,rule in ipairs(black_ip_rule) do
				if rule ~= "" and client_ip == rule then
					log_record("black ip",ngx.var.request_uri,client_ip,rule)
					if config_waf_status == "on" then
						ngx.exit(403)
					end
				end
			end
		end
	end
end