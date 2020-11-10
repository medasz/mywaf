-- 修改http请求头Server字段
ngx.header['Server'] = "mywaf"
-- 规则检测
mywaf.check()