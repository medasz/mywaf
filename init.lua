require "config"

----常用函数-----
local optionIsOn=function(option) return option =="on" end
local match=string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_header=ngx.req.get_headers
----配置导入-----
attacklog=optionIsOn(attacklog)
logpath=logdir
rulepath=RulePath
CCDeny=optionIsOn(CCDeny)
whiteModule=optionIsOn(whiteModule)
UriDeny=optionIsOn(UriDeny)
Redirect=optionIsOn(Redirect)
CookieMatch=optionIsOn(CookieMatch)
postMatch=optionIsOn(postMatch)

----读取规则-----
function readrule(filename)
	local fd = io.open(rulepath.."/"..filename)
	if fd ==nil then
		return
	end
	local t={}
	for line in fd:lines() do
		table.insert(t,line)
	end
	fd:close()
	return(t)
end
----规则导入-----
wturirules=readrule("whiteuri")
urirules=readrule("uri")
uarules=readrule("user-agent")
cookierules=readrule("cookie")
argsrules=readrule("args")
postrules=readrule("post")
----获取远程ip地址----
function getRemoteIp()
	local remoteIp=ngx.var.remote_addr
	if remoteIp == nil then
		remoteIp = "unknow"
	end
	return remoteIp
end
----文件写入-----
function write(filename,msg)
	if msg ~=nil then
		local fd = io.open(filename,"ab")
		if fd == nil then
			return
		end
		fd:write(msg)
		fd:flush()
		fd:close()
	end
end
----记录日志-----
--./servername_xxxx-xx-xx_sec.log
--x.x.x.x [xxxx-xx-xx xx:xx:xx] "method servernameurl" "data" "user-agent" "ruletag"\n
function log(method,url,data,ruletag)
	if attacklog then
		local msg=nil
		local remoteIp=getRemoteIp()
		local ua=ngx.var.http_user_agent
		local time=ngx.localtime()
		local servername=ngx.var.server_name
		if ua then
			msg=remoteIp.." ["..time.."] ".."\""..method.." "..servername..url.."\" ".."\""..data.."\" ".."\""..ua.."\" ".."\""..ruletag.."\"\n"
		else
			msg=remoteIp.." ["..time.."] ".."\""..method.." "..servername..url.."\" ".."\""..data.."\" ".."\""..ruletag.."\"\n"
		end
		local filename=logpath.."/"..servername.."_"..ngx.today().."_sec.log"
		write(filename,msg)
	end
end
----请求拦截显示页面----
function say_html()
	if Redirect then
		ngx.header.content_type="text/html"
		ngx.status=ngx.HTTP_FORBIDDEN
		ngx.say(html)
		ngx.exit(ngx.status)
	end
end
----ip白名单------
function whiteip()
	if next(ipWhiteList)~=nil then
		for _,val in ipairs(ipWhiteList) do
			if val == getRemoteIp() then
				return true
			end 
		end
	end
	return false
end
----ip黑名单-----
function blackip()
	if next(ipBlackList)~=nil then
		for _,val in ipairs(ipBlackList) do
			if val == getRemoteIp() then
				ngx.exit(403)
				return true
			end
		end
	end
	return false	
end
----CCdeny-----
function denycc()
	if CCDeny then
		local token=getRemoteIp()..ngx.var.uri
		local limit=ngx.shared.limit
		local req,_=limit:get(token)
		local CCcount=tonumber(match(CCrate,"(.*)/"))
		local CCseconds=tonumber(match(CCrate,"/(.*)"))
		if req then
			if req > CCcount then
				ngx.exit(503)
				return true
			else
				limit:incr(token,1)
			end
		else		
			limit:set(token,1,CCseconds)
		end
	end
	return false
end
----white uri-----
function whiteuri()
	if whiteModule then
		if wturirules ~= nil then
			for _,rule in ipairs(wturirules) do
				if ngxmatch(ngx.var.uri,rule,"isjo") then
					return true
				end
			end
		end
	end
	return false
end
----black uri----
function blackuri()
	if UriDeny then
		local uriTmp=ngx.var.request_uri
		for _,rule in ipairs(urirules) do
			if rule~="" and ngxmatch(uriTmp,rule,"isjo") then
				log(ngx.req.get_method,uriTmp,"-",rule)
				say_html()
				return true
			end
		end
	end
end
----user-agent黑名单检测-----
function blackuseragent()
	local ua=ngx.var.http_user_agent
	if ua then
		for _,rule in ipairs(uarules) do
			if rule ~= "" and ngxmatch(ua,rule,"isjo") then
				log(ngx.req.get_method(),ngx.var.request_uri,ua,rule)
				say_html()
				return true
			end
		end
	end
	return false
end
----cookie黑名单------
function blackcookie()
	local cookie=ngx.var.http_cookie
	if CookieMatch and cookie then
		for _,rule in ipairs(cookierules) do
			if rule~='' and ngxmatch(cookie,rule,"isjo") then
				log(ngx.req.get_method(),ngx.var.request_uri,cookie,rule)
				say_html()
				return true
			end
		end
	end
	return false
end
----args请求参数黑名单------
function blackargs()
	local args = ngx.req.get_uri_args()
	for _,rule in ipairs(argsrules) do
		for key,val in pairs(args) do
			local data = nil
			if type(val) == 'table' then
				local t={}
				for k,v in pairs(val) do
					if v==true then
						v=""
					end
					table.insert(t,v)
				end
				data=table.concat(t," ")
			else
				data=val
			end
			if data and type(data) ~='boolean' and rule ~= "" and ngxmatch(unescape(data),rule,'isjo') then
				log(ngx.req.get_method(),ngx.var.request_uri,unescape(data),rule)
				say_html()
				return true
			end
		end
	end
	return false
end
----post请求体检测函数------
----获取post请求头content-type中的boundary的值------
function get_boundary()
	local header=get_header()['Content-Type']
	if not header then
		return nil
	end
	if type(header) == 'table' then
		header=header[1]
	end
	local m= match(header,";%s*boundary=\"([^\"]+)\"")
	if m then
		return m
	end
	return match(header,";%s*boundary=([^\",;]+)")
end
----匹配post黑名单--------
function body(data)
	for _,rule in ipairs(postrules) do
		if rule ~="" and data ~="" and ngxmatch(unescape(data),rule,"isjo") then
			log(ngx.req.get_method(),ngx.var.request_uri,unescape(data),rule)
			say_html()
			return true
		end
	end
	return false
end
----检查文件后缀名-----
function fileExtCheck(ext)
	local items=set(black_fileExt)
	ext=string.lower(ext)
	if ext then
		for rule in pairs(items) do
			if ext~="" and ngxmatch(ext,rule,"isjo") then
				log(ngx.req.get_method(),ngx.var.request_uri,ext,"file attack with ext"..rule)
				say_html()
			end
		end
	end
end
----数组去重------
function set(list)
	local t={}
	for _,val in ipairs(list) do
		t[val]=true
	end
	return t
end
