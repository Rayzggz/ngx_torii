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
-  In addition to treating the 445 HTTP code as access denied like the 403, everything else is completely the same as `ngx_http_auth_request_module`.
-  If the subrequest returns 445, access is denied with the 445 error code. This is specific to [server_torii](https://github.com/Rayzggz/server_torii). and indicates that the request was blocked by server_torii.
- Using the C preprocessor, mixed with changes from `ngx_http_auth_request_module` that occurred in Nginx 1.23, to make the current module compatible with all versions of Nginx from 1.10 onwards.



