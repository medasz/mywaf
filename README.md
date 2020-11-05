# mywaf
一个简单的waf，完成unixhot的waf中post请求体检查部分

# 安装
### 安装openresty
```shell

```

# 检查
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```

# 配置文件讲解

# 历史版本说明
1. 第一个版本
对[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)进行一些小的修改
2. 第二个版本
上传了ngx_lua_waf的流程模块
3. 第三个版本
修改一些函数实现，上传了规则
4. 第四个版本
修改整体设计，主要是根据[unixhot的waf](https://github.com/unixhot/waf.git)

# TODO
1. 规则存储到数据库
2. waf管理界面
3. 结果展示
4. unixhot的waf中没有请求体检查

# About
1. 第一，二，三个版本是基于loveshell的ngx_lua_waf修改的
2. 第四个版本是基于unixhot的waf修改的
3. 第五个版本是基于xsec-lab的x-waf和x-waf-admin修改的
