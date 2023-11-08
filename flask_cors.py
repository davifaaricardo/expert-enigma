from urllib.parse import unquote_plus
from . import request, current_app
from collections.abc import Iterable
from datetime import timedelta
from werkzeug.datastructures import Headers, MultiDict
import re
class core:
    def __init__(self,debug):
        self.debug=debug
    def parse_resources(self,resources):
        if isinstance(resources, dict):
            resources = [(self.re_fix(k), v) for k, v in resources.items()]
            def pattern_length(pair):
                maybe_regex,_=pair
                return len(self.get_regexp_pattern(maybe_regex))
            return sorted(resources,key=pattern_length,reverse=True)
        elif isinstance(resources, str):return [(self.re_fix(resources), {})]
        elif isinstance(resources, Iterable):return [(self.re_fix(r), {}) for r in resources]
        elif isinstance(resources,  type(re.compile(''))):return [(self.re_fix(resources), {})]
        else:raise ValueError("Unexpected value for resources argument.")
    def get_regexp_pattern(self,regexp):
        try:return regexp.pattern
        except AttributeError:return str(regexp)
    def get_cors_origins(self,options, request_origin):
        origins = options.get('origins')
        wildcard = r'.*' in origins
        if request_origin:
            if self.debug:print("CORS request received with 'Origin' %s", request_origin)
            if wildcard and options.get('send_wildcard'):
                if self.debug:print("Allowed origins are set to '*'. Sending wildcard CORS header.")
                return ['*']
            elif self.try_match_any(request_origin, origins):
                if self.debug:print("The request's Origin header matches. Sending CORS headers.",)
                return [request_origin]
            else:
                if self.debug:print("The request's Origin header does not match any of allowed origins.")
                return None
        elif options.get('always_send'):
            if wildcard:
                if options.get('supports_credentials'):return None
                else:return ['*']
            else:return sorted([o for o in origins if not self.probably_regex(o)])
        else:
            if self.debug:print("The request did not contain an 'Origin' header. This means the browser or client did not request CORS, ensure the Origin Header is set.")
            return None
    def get_allow_headers(self,options, acl_request_headers):
        if acl_request_headers:
            request_headers=[h.strip() for h in acl_request_headers.split(',')]
            matching_headers=filter(lambda h: self.try_match_any(h, options.get('allow_headers')),request_headers)
            return ', '.join(sorted(matching_headers))
        return None
    def get_cors_headers(self,options, request_headers, request_method):
        origins_to_set = self.get_cors_origins(options, request_headers.get('Origin'))
        headers = MultiDict()
        if not origins_to_set:return headers
        for origin in origins_to_set:headers.add('Access-Control-Allow-Origin', origin)
        headers['Access-Control-Expose-Headers'] = options.get('expose_headers')
        if options.get('supports_credentials'):headers['Access-Control-Allow-Credentials'] = 'true'  # case sensitive
        if 'Access-Control-Request-Private-Network' in request_headers and request_headers.get('Access-Control-Request-Private-Network') == 'true':
            headers['Access-Control-Allow-Private-Network'] = 'true'
        if request_method == 'OPTIONS':
            acl_request_method = request_headers.get('Access-Control-Request-Method', '').upper()
            if acl_request_method and acl_request_method in options.get('methods'):
                headers['Access-Control-Allow-Headers'] = self.get_allow_headers(options, request_headers.get('Access-Control-Request-Headers'))
                headers['Access-Control-Max-Age'] = options.get('max_age')
                headers['Access-Control-Allow-Methods'] = options.get('methods')
            else:
                if self.debug:print("The request's Access-Control-Request-Method header does not match allowed methods. CORS headers will not be applied.")
        if options.get('vary_header'):
            if headers['Access-Control-Allow-Origin'] == '*':
                pass
            elif (len(options.get('origins')) > 1 or
                len(origins_to_set) > 1 or
                any(map(self.probably_regex, options.get('origins')))):
                headers.add('Vary', 'Origin')
        return MultiDict((k, v) for k, v in headers.items() if v)
    def set_cors_headers(self,resp, options):
        if hasattr(resp, '_FLASK_CORS_EVALUATED'):
            if self.debug:print('CORS have been already evaluated, skipping')
            return resp
        if (not isinstance(resp.headers, Headers) and not isinstance(resp.headers, MultiDict)):resp.headers = MultiDict(resp.headers)
        headers_to_set = self.get_cors_headers(options, request.headers, request.method)
        if self.debug:print('Settings CORS headers: %s', str(headers_to_set))
        for k, v in headers_to_set.items():resp.headers.add(k, v)
        return resp
    def probably_regex(self,maybe_regex):
        if isinstance(maybe_regex, type(re.compile(''))):return True
        else:return any((c in maybe_regex for c in ['*', '\\', ']', '?', '$', '^', '[', ']', '(', ')']))
    def re_fix(self,reg): r'.*' if reg == r'*' else reg
    def try_match_any(self,inst, patterns):return any(self.try_match(inst, pattern) for pattern in patterns)
    def try_match(self,request_origin, maybe_regex):
        if isinstance(maybe_regex, type(re.compile(''))):return re.match(maybe_regex, request_origin)
        elif self.probably_regex(maybe_regex):return re.match(maybe_regex, request_origin, flags=re.IGNORECASE)
        else:
            try:return request_origin.lower() == maybe_regex.lower()
            except AttributeError:return request_origin == maybe_regex
    def get_cors_options(self,appInstance, *dicts):
        options = dict(origins='*',methods=['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'],allow_headers='*',expose_headers=None,supports_credentials=False,max_age=None,send_wildcard=False,automatic_options=True,vary_header=True,resources=r'/*',intercept_exceptions=True,always_send=True).copy()
        options.update(self.get_app_kwarg_dict(appInstance))
        if dicts:
            for d in dicts:options.update(d)
        return self.serialize_options(options)
    def get_app_kwarg_dict(self,appInstance=None):
        app = (appInstance or current_app)
        app_config = getattr(app, 'config', {})
        return {k.lower().replace('cors_', ''): app_config.get(k) for k in ['CORS_ORIGINS', 'CORS_METHODS', 'CORS_ALLOW_HEADERS','CORS_EXPOSE_HEADERS', 'CORS_SUPPORTS_CREDENTIALS','CORS_MAX_AGE', 'CORS_SEND_WILDCARD','CORS_AUTOMATIC_OPTIONS', 'CORS_VARY_HEADER','CORS_RESOURCES', 'CORS_INTERCEPT_EXCEPTIONS','CORS_ALWAYS_SEND'] if app_config.get(k) is not None}
    def flexible_str(self,obj):
        if obj is None:return None
        elif not isinstance(obj, str) and isinstance(obj, Iterable):return ", ".join(str(item) for item in sorted(obj))
        else:return str(obj)
    def serialize_option(self,options_dict, key, upper=False):
        if key in options_dict:
            value = self.flexible_str(options_dict[key])
            options_dict[key] = value.upper() if upper else value
    def ensure_iterable(self,inst):
        if isinstance(inst, str):return [inst]
        elif not isinstance(inst, Iterable):return [inst]
        else:return inst
    def sanitize_regex_param(self,param):return [self.re_fix(x) for x in self.ensure_iterable(param)]
    def serialize_options(self,opts):
        options = (opts or {}).copy()
        for key in opts.keys():
            if key not in dict(origins='*',methods=['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'],allow_headers='*',expose_headers=None,supports_credentials=False,max_age=None,send_wildcard=False,automatic_options=True,vary_header=True,resources=r'/*',intercept_exceptions=True,always_send=True):
                if self.debug:print("Unknown option passed to Flask-CORS: %s", key)
        options['origins'] = self.sanitize_regex_param(options.get('origins'))
        options['allow_headers'] = self.sanitize_regex_param(options.get('allow_headers'))
        if r'.*' in options['origins'] and options['supports_credentials'] and options['send_wildcard']:raise ValueError("Cannot use supports_credentials in conjunction with an origin string of '*'. See: http://www.w3.org/TR/cors/#resource-requests")
        self.serialize_option(options, 'expose_headers')
        self.serialize_option(options, 'methods', upper=True)
        if isinstance(options.get('max_age'), timedelta):options['max_age'] = str(int(options['max_age'].total_seconds()))
        return options
class CORS:
    def __init__(self, app=None,debug:bool=False,**kwargs):
        self._options = kwargs
        cor = core(debug)
        get_cors_options = cor.get_cors_options
        parse_resources = cor.parse_resources
        get_regexp_pattern = cor.get_regexp_pattern
        if app is not None:
            options = get_cors_options(app, self._options, kwargs)
            resources = parse_resources(options.get('resources'))
            resources = [(pattern, get_cors_options(app, options, opts))for (pattern, opts) in resources]
            if debug == True:
                resources_human = {get_regexp_pattern(pattern): opts for (pattern,opts) in resources}
                print(f"Configuring CORS with resources: {resources_human}")
            cors_after_request = self.make_after_request_function(resources,debug)
            app.after_request(cors_after_request)
            if options.get('intercept_exceptions', True):
                def _after_request_decorator(f):
                    def wrapped_function(*args, **kwargs):return cors_after_request(app.make_response(f(*args, **kwargs)))
                    return wrapped_function
                if hasattr(app, 'handle_exception'):
                    app.handle_exception = _after_request_decorator(app.handle_exception)
                    app.handle_user_exception = _after_request_decorator(app.handle_user_exception)
    def make_after_request_function(self,resources,debug):
        cor = core(debug)
        set_cors_headers = cor.set_cors_headers
        try_match = cor.try_match
        get_regexp_pattern = cor.get_regexp_pattern
        def cors_after_requestor(resp):
            if resp.headers is not None and resp.headers.get('Access-Control-Allow-Origin'):
                if debug:print('CORS have been already evaluated, skipping')
                return resp
            normalized_path = unquote_plus(request.path)
            for res_regex, res_options in resources:
                if try_match(normalized_path, res_regex):
                    if debug:print(f"Request to '{request.path}' matches CORS resource '{get_regexp_pattern(res_regex)}'. Using options: {res_options}")
                    set_cors_headers(resp, res_options)
                    break
            else:
                if debug:print('No CORS rule matches')
            return resp
        return cors_after_requestor                