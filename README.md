# ⛩️ngx_torii 

## Overview

This module is a modified version of the `ngx_http_auth_request_module` to serve as the Nginx connector for [server_torii](https://github.com/Rayzggz/server_torii).


## Directives

```nginx
Syntax:    torii_auth_request uri | off;
Default:   torii_auth_request off;
Context:   http, server, location
```


```nginx
Syntax:    torii_auth_request_set $variable value;
Default:   —
Context:   http, server, location
```


## Usage Notes
-  Use in the same way as `ngx_http_auth_request_module`.
- Unlike the `ngx_http_auth_request_module`, non-200 responses returned by the auth service will be sent directly to the client.



