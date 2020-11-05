require 'config'
require 'tools'

function white_ip_check()
	if config_white_ip_status == "on" then
		local client_ip 	= 	get_client_ip()
		local white_ip_rule	=	get_rule("white_ip.rule")
		if white_ip_rule ~= nil then
			for _,rule in ipairs(white_ip_rule) do
				if rule ~= "" and client_ip == rule then
					log_record("white ip",ngx.unescape_uri(ngx.var.request_uri),client_ip,rule)
					return true
				end
			end
		end
	end
end