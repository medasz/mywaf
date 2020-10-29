ngx.header["Server"] = "mywaf"
if whiteip() then
elseif blackip() then
elseif denycc() then
elseif ngx.var.http_Acunetix_Aspect then
	ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
	ngx.exit(444)
elseif whiteuri() then
elseif blackuseragent() then
elseif blackuri() then
elseif blackargs() then
elseif blackcookie() then
elseif postMatch then
	if ngx.req.get_method()=="POST" then
		local boundary = get_boundary()
		if boundary then
			local sock,err=ngx.req.socket()
			if not sock then
				return
			end
			ngx.req.init_body()
			sock:settimeout(0)
			local content_length=tonumber(ngx.req.get_headers()['content-length'])
			local chunk_size=4096
			local size=0
			if content_length<chunk_size then
				chunk_size=content_length
			end
			while size < content_length do
				local data,err,partial =sock:receive(chunk_size)
				data =data or partial
				if not data then
					return
				end
				ngx.req.append_body(data)
				if body(data) then
					return true
				end
				size=size+#data
				local m=ngx.re.match(data,"Content-Disposition: form-data;(.+)filename=\"(.+)\\.(.*)\"","ijo")
				local filetranslate=true
				if m then
					fileExtCheck(m[3])
					filetranslate=false
				else
					if not ngx.re.match(data,"Content-Disposition:","isjo") then
						filetranslate=true
					else
						filetranslate=false
					end
				end
				if filetranslate then
					if body(data) then
						return true
					end
				end
				local less =content_length - size
				if less < chunk_size then
					chunk_size=less
				end
			end
			ngx.req.finish_body()
		else
			ngx.req.read_body()
			local args=ngx.req.get_post_args()
			if 	not args then
				return
			end
			for k,v in pairs(args) do
				local data = nil
				if type(v) == 'table' then
					local t ={}
					for _,val in ipairs(v) do
						if val ==true then
							val = ""
						end
						table.insert(t,val)
					end
					data=table.concat(t,", ")
				else
					data=v
				end
				if data and type(data) ~= 'boolean' and body(data) then
					body(key)
				end
			end
		end	
	end	
else
	return
end
