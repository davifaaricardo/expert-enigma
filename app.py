import functools,inspect,logging,os,sys,weakref,json,warnings,click,typing as t
from . import json
from collections.abc import Iterator as _abc_Iterator
from datetime import timedelta
from itertools import chain
from threading import Lock
from types import TracebackType
from werkzeug.datastructures import Headers,ImmutableDict
from werkzeug.exceptions import Aborter,BadRequest,BadRequestKeyError,HTTPException,InternalServerError
from werkzeug.routing import BuildError,Map,MapAdapter,RequestRedirect,RoutingException,Rule
from werkzeug.serving import is_running_from_reloader,run_simple
from werkzeug.urls import url_quote
from werkzeug.utils import redirect as _wz_redirect
from werkzeug.wrappers import Response as BaseResponse
from .flask_cors import CORS
from .testing import EnvironBuilder
from . import cli
from . import typing as ft
from .config import Config
from .config import ConfigAttribute
from .ctx import _AppCtxGlobals
from .ctx import AppContext
from .ctx import RequestContext
from .globals import _cv_app
from .globals import _cv_request
from .globals import g
from .globals import request
from .globals import request_ctx
from .globals import session
from .helpers import _split_blueprint_path
from .helpers import get_debug_flag
from .helpers import get_flashed_messages
from .helpers import get_load_dotenv
from .helpers import locked_cached_property
from .json.provider import DefaultJSONProvider
from .json.provider import JSONProvider
from .logging import create_logger
from .scaffold import _endpoint_from_view_func
from .scaffold import _sentinel
from .scaffold import find_package
from .scaffold import Scaffold
from .scaffold import setupmethod
from .sessions import SecureCookieSessionInterface
from .sessions import SessionInterface
from .signals import appcontext_tearing_down
from .signals import got_request_exception
from .signals import request_finished
from .signals import request_started
from .signals import request_tearing_down
from .templating import DispatchingJinjaLoader
from .templating import Environment
from .wrappers import Request
from .wrappers import Response
if t.TYPE_CHECKING:
    import typing_extensions as te
    from .blueprints import Blueprint
    from .testing import FlaskClient
    from .testing import FlaskCliRunner
T_before_first_request = t.TypeVar(
    "T_before_first_request", bound=ft.BeforeFirstRequestCallable
)
T_shell_context_processor = t.TypeVar(
    "T_shell_context_processor", bound=ft.ShellContextProcessorCallable
)
T_teardown = t.TypeVar("T_teardown", bound=ft.TeardownCallable)
T_template_filter = t.TypeVar("T_template_filter", bound=ft.TemplateFilterCallable)
T_template_global = t.TypeVar("T_template_global", bound=ft.TemplateGlobalCallable)
T_template_test = t.TypeVar("T_template_test", bound=ft.TemplateTestCallable)

if sys.version_info >= (3, 8):
    iscoroutinefunction = inspect.iscoroutinefunction
else:

    def iscoroutinefunction(func: t.Any) -> bool:
        while inspect.ismethod(func):
            func = func.__func__

        while isinstance(func, functools.partial):
            func = func.func

        return inspect.iscoroutinefunction(func)


def _make_timedelta(value: t.Union[timedelta, int, None]) -> t.Optional[timedelta]:
    if value is None or isinstance(value, timedelta):
        return value

    return timedelta(seconds=value)


class Flask(Scaffold):
    request_class = Request
    response_class = Response
    aborter_class = Aborter
    jinja_environment = Environment
    app_ctx_globals_class = _AppCtxGlobals
    config_class = Config
    testing = ConfigAttribute("TESTING")
    secret_key = ConfigAttribute("SECRET_KEY")

    @property
    def session_cookie_name(self) -> str:

        warnings.warn(
            "'session_cookie_name' is deprecated and will be removed in Flask 2.3. Use"
            " 'SESSION_COOKIE_NAME' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.config["SESSION_COOKIE_NAME"]

    @session_cookie_name.setter
    def session_cookie_name(self, value: str) -> None:

        warnings.warn(
            "'session_cookie_name' is deprecated and will be removed in Flask 2.3. Use"
            " 'SESSION_COOKIE_NAME' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.config["SESSION_COOKIE_NAME"] = value

    permanent_session_lifetime = ConfigAttribute(
        "PERMANENT_SESSION_LIFETIME", get_converter=_make_timedelta
    )

    @property
    def send_file_max_age_default(self) -> t.Optional[timedelta]:

        warnings.warn(
            "'send_file_max_age_default' is deprecated and will be removed in Flask"
            " 2.3. Use 'SEND_FILE_MAX_AGE_DEFAULT' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return _make_timedelta(self.config["SEND_FILE_MAX_AGE_DEFAULT"])

    @send_file_max_age_default.setter
    def send_file_max_age_default(self, value: t.Union[int, timedelta, None]) -> None:

        warnings.warn(
            "'send_file_max_age_default' is deprecated and will be removed in Flask"
            " 2.3. Use 'SEND_FILE_MAX_AGE_DEFAULT' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.config["SEND_FILE_MAX_AGE_DEFAULT"] = _make_timedelta(value)

    @property
    def use_x_sendfile(self) -> bool:

        warnings.warn(
            "'use_x_sendfile' is deprecated and will be removed in Flask 2.3. Use"
            " 'USE_X_SENDFILE' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.config["USE_X_SENDFILE"]

    @use_x_sendfile.setter
    def use_x_sendfile(self, value: bool) -> None:

        warnings.warn(
            "'use_x_sendfile' is deprecated and will be removed in Flask 2.3. Use"
            " 'USE_X_SENDFILE' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.config["USE_X_SENDFILE"] = value

    _json_encoder: t.Union[t.Type[json.JSONEncoder], None] = None
    _json_decoder: t.Union[t.Type[json.JSONDecoder], None] = None

    @property  
    def json_encoder(self) -> t.Type[json.JSONEncoder]:

        warnings.warn(
            "'app.json_encoder' is deprecated and will be removed in Flask 2.3."
            " Customize 'app.json_provider_class' or 'app.json' instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        if self._json_encoder is None:
            

            return json.JSONEncoder

        return self._json_encoder

    @json_encoder.setter
    def json_encoder(self, value: t.Type[json.JSONEncoder]) -> None:
        warnings.warn(
            "'app.json_encoder' is deprecated and will be removed in Flask 2.3."
            " Customize 'app.json_provider_class' or 'app.json' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._json_encoder = value

    @property
    def json_decoder(self) -> t.Type[json.JSONDecoder]: 

        warnings.warn(
            "'app.json_decoder' is deprecated and will be removed in Flask 2.3."
            " Customize 'app.json_provider_class' or 'app.json' instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        if self._json_decoder is None:

            return json.JSONDecoder

        return self._json_decoder

    @json_decoder.setter
    def json_decoder(self, value: t.Type[json.JSONDecoder]) -> None:

        warnings.warn(
            "'app.json_decoder' is deprecated and will be removed in Flask 2.3."
            " Customize 'app.json_provider_class' or 'app.json' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._json_decoder = value

    json_provider_class: t.Type[JSONProvider] = DefaultJSONProvider
    jinja_options: dict = {}
    default_config = ImmutableDict(
        {
            "ENV": None,
            "DEBUG": None,
            "TESTING": False,
            "PROPAGATE_EXCEPTIONS": None,
            "SECRET_KEY": None,
            "PERMANENT_SESSION_LIFETIME": timedelta(days=31),
            "USE_X_SENDFILE": False,
            "SERVER_NAME": None,
            "APPLICATION_ROOT": "/",
            "SESSION_COOKIE_NAME": "session",
            "SESSION_COOKIE_DOMAIN": None,
            "SESSION_COOKIE_PATH": None,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SECURE": False,
            "SESSION_COOKIE_SAMESITE": None,
            "SESSION_REFRESH_EACH_REQUEST": True,
            "MAX_CONTENT_LENGTH": None,
            "SEND_FILE_MAX_AGE_DEFAULT": None,
            "TRAP_BAD_REQUEST_ERRORS": None,
            "TRAP_HTTP_EXCEPTIONS": False,
            "EXPLAIN_TEMPLATE_LOADING": False,
            "PREFERRED_URL_SCHEME": "http",
            "JSON_AS_ASCII": None,
            "JSON_SORT_KEYS": None,
            "JSONIFY_PRETTYPRINT_REGULAR": None,
            "JSONIFY_MIMETYPE": None,
            "TEMPLATES_AUTO_RELOAD": None,
            "MAX_COOKIE_SIZE": 4093,
        }
    )
    url_rule_class = Rule
    url_map_class = Map
    test_client_class: t.Optional[t.Type["FlaskClient"]] = None
    test_cli_runner_class: t.Optional[t.Type["FlaskCliRunner"]] = None
    session_interface: SessionInterface = SecureCookieSessionInterface()

    def __init__(
        self,
        import_name: str,
        static_url_path: t.Optional[str] = None,
        static_folder: t.Optional[t.Union[str, os.PathLike]] = "static",
        static_host: t.Optional[str] = None,
        host_matching: bool = False,
        subdomain_matching: bool = False,
        template_folder: t.Optional[str] = "templates",
        instance_path: t.Optional[str] = None,
        instance_relative_config: bool = False,
        root_path: t.Optional[str] = None,
    ):
        super().__init__(
            import_name=import_name,
            static_folder=static_folder,
            static_url_path=static_url_path,
            template_folder=template_folder,
            root_path=root_path,
        )
        if instance_path is None:instance_path = self.auto_find_instance_path()
        elif not os.path.isabs(instance_path):raise ValueError("If an instance path is provided it must be absolute.\n A relative path was given instead.")
        self.instance_path = instance_path
        self.config = self.make_config(instance_relative_config)
        self.aborter = self.make_aborter()
        self.json: JSONProvider = self.json_provider_class(self)
        self.url_build_error_handlers: t.List[t.Callable[[Exception,str,t.Dict[str,t.Any]],str]]=[]
        self.before_first_request_funcs: t.List[ft.BeforeFirstRequestCallable] = []
        self.teardown_appcontext_funcs: t.List[ft.TeardownCallable] = []
        self.shell_context_processors: t.List[ft.ShellContextProcessorCallable] = []
        self.blueprints: t.Dict[str, "Blueprint"] = {}
        self.extensions: dict = {}
        self.url_map = self.url_map_class()
        self.url_map.host_matching = host_matching
        self.subdomain_matching = subdomain_matching
        self._got_first_request = False
        self._before_request_lock = Lock()
        if self.has_static_folder:
            assert (
                bool(static_host) == host_matching
            ), "Invalid static_host/host_matching combination"
            self_ref = weakref.ref(self)
            self.add_url_rule(
                f"{self.static_url_path}/<path:filename>",
                endpoint="static",
                host=static_host,
                view_func=lambda **kw: self_ref().send_static_file(**kw),)
        self.cli.name = self.name

    def _check_setup_finished(self, f_name: str) -> None:
        if self._got_first_request:
            raise AssertionError(
                f"The setup method '{f_name}' can no longer be called"
                " on the application. It has already handled its first"
                " request, any changes will not be applied"
                " consistently.\n"
                "Make sure all imports, decorators, functions, etc."
                " needed to set up the application are done before"
                " running it."
            )

    @locked_cached_property
    def name(self) -> str:  
        if self.import_name == "__main__":
            fn = getattr(sys.modules["__main__"], "__file__", None)
            if fn is None:
                return "__main__"
            return os.path.splitext(os.path.basename(fn))[0]
        return self.import_name

    @property
    def propagate_exceptions(self) -> bool:

        warnings.warn(
            "'propagate_exceptions' is deprecated and will be removed in Flask 2.3.",
            DeprecationWarning,
            stacklevel=2,
        )
        rv = self.config["PROPAGATE_EXCEPTIONS"]
        if rv is not None:
            return rv
        return self.testing or self.debug

    @locked_cached_property
    def logger(self) -> logging.Logger:
        return create_logger(self)

    @locked_cached_property
    def jinja_env(self) -> Environment:
        return self.create_jinja_environment()

    @property
    def got_first_request(self) -> bool:
        return self._got_first_request

    def make_config(self, instance_relative: bool = False) -> Config:
        root_path = self.root_path
        if instance_relative:
            root_path = self.instance_path
        defaults = dict(self.default_config)
        defaults["ENV"] = os.environ.get("FLASK_ENV") or "production"
        defaults["DEBUG"] = get_debug_flag()
        return self.config_class(root_path, defaults)

    def make_aborter(self) -> Aborter:return self.aborter_class()

    def auto_find_instance_path(self) -> str:
        prefix, package_path = find_package(self.import_name)
        if prefix is None:return os.path.join(package_path, "instance")
        return os.path.join(prefix, "var", f"{self.name}-instance")

    def open_instance_resource(self, resource: str, mode: str = "rb") -> t.IO[t.AnyStr]:
        return open(os.path.join(self.instance_path, resource), mode)

    @property
    def templates_auto_reload(self) -> bool:
        warnings.warn(
            "'templates_auto_reload' is deprecated and will be removed in Flask 2.3."
            " Use 'TEMPLATES_AUTO_RELOAD' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        rv = self.config["TEMPLATES_AUTO_RELOAD"]
        return rv if rv is not None else self.debug
    @templates_auto_reload.setter
    def templates_auto_reload(self, value: bool) -> None:

        warnings.warn(
            "'templates_auto_reload' is deprecated and will be removed in Flask 2.3."
            " Use 'TEMPLATES_AUTO_RELOAD' in 'app.config' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.config["TEMPLATES_AUTO_RELOAD"] = value

    def create_jinja_environment(self) -> Environment:
        options = dict(self.jinja_options)

        if "autoescape" not in options:
            options["autoescape"] = self.select_jinja_autoescape

        if "auto_reload" not in options:
            auto_reload = self.config["TEMPLATES_AUTO_RELOAD"]

            if auto_reload is None:
                auto_reload = self.debug

            options["auto_reload"] = auto_reload

        rv = self.jinja_environment(self, **options)
        rv.globals.update(
            url_for=self.url_for,
            get_flashed_messages=get_flashed_messages,
            config=self.config,
            request=request,
            session=session,
            g=g,
        )
        rv.policies["json.dumps_function"] = self.json.dumps
        return rv

    def create_global_jinja_loader(self) -> DispatchingJinjaLoader:
        return DispatchingJinjaLoader(self)

    def select_jinja_autoescape(self, filename: str) -> bool:
        if filename is None:
            return True
        return filename.endswith((".html", ".htm", ".xml", ".xhtml"))

    def update_template_context(self, context: dict) -> None:
        names: t.Iterable[t.Optional[str]] = (None,)
        if request:
            names = chain(names, reversed(request.blueprints))
        orig_ctx = context.copy()

        for name in names:
            if name in self.template_context_processors:
                for func in self.template_context_processors[name]:
                    context.update(func())

        context.update(orig_ctx)

    def make_shell_context(self) -> dict:
        rv = {"app": self, "g": g}
        for processor in self.shell_context_processors:
            rv.update(processor())
        return rv

    @property
    def env(self) -> str:

        warnings.warn(
            "'app.env' is deprecated and will be removed in Flask 2.3."
            " Use 'app.debug' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.config["ENV"]

    @env.setter
    def env(self, value: str) -> None:

        warnings.warn(
            "'app.env' is deprecated and will be removed in Flask 2.3."
            " Use 'app.debug' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.config["ENV"] = value

    @property
    def debug(self) -> bool:
        return self.config["DEBUG"]

    @debug.setter
    def debug(self, value: bool) -> None:
        self.config["DEBUG"] = value

        if self.config["TEMPLATES_AUTO_RELOAD"] is None:
            self.jinja_env.auto_reload = value

    def run(
        self,
        host: t.Optional[str] = None,
        port: t.Optional[int] = None,
        debug: t.Optional[bool] = None,
        load_dotenv: bool = True,
        cors_enabled: t.Optional[bool] = False,
        **options: t.Any,
    ) -> None:
        if os.environ.get("FLASK_RUN_FROM_CLI") == "true":
            if not is_running_from_reloader():
                click.secho(
                    " * Ignoring a call to 'app.run()' that would block"
                    " the current 'flask' CLI command.\n"
                    "   Only call 'app.run()' in an 'if __name__ =="
                    ' "__main__"\' guard.',
                    fg="red",
                )

            return

        if get_load_dotenv(load_dotenv):
            cli.load_dotenv()
            if "FLASK_ENV" in os.environ:
                print(
                    "'FLASK_ENV' is deprecated and will not be used in"
                    " Flask 2.3. Use 'FLASK_DEBUG' instead.",
                    file=sys.stderr,
                )
                self.config["ENV"] = os.environ.get("FLASK_ENV") or "production"
                self.debug = get_debug_flag()
            elif "FLASK_DEBUG" in os.environ:
                self.debug = get_debug_flag()

        if debug is not None:
            self.debug = bool(debug)
        
        if cors_enabled is not None:cors_enabled = bool(cors_enabled)
        cors = ' * Cors requests enabled: '
        if cors_enabled == True:
            CORS(self,debug)
            cors+='Yes'
        else:cors+='No'    
        print(cors)
        server_name = self.config.get("SERVER_NAME")
        sn_host = sn_port = None
        if server_name:
            sn_host, _, sn_port = server_name.partition(":")

        if not host:
            if sn_host:
                host = sn_host
            else:
                host = "127.0.0.1"

        if port or port == 0:
            port = int(port)
        elif sn_port:
            port = int(sn_port)
        else:
            port = 5000

        options.setdefault("use_reloader", self.debug)
        options.setdefault("use_debugger", self.debug)
        options.setdefault("threaded", True)

        cli.show_server_banner(self.debug, self.name)

        

        try:run_simple(t.cast(str, host), port, self, **options)
        finally:self._got_first_request = False

    def test_client(self, use_cookies: bool = True, **kwargs: t.Any) -> "FlaskClient":
        cls = self.test_client_class
        if cls is None:
            from .testing import FlaskClient as cls 
        return cls(  
            self, self.response_class, use_cookies=use_cookies, **kwargs
        )
    def test_cli_runner(self, **kwargs: t.Any) -> "FlaskCliRunner":
        cls = self.test_cli_runner_class
        if cls is None:from .testing import FlaskCliRunner as cls
        return cls(self, **kwargs)  
    @setupmethod
    def register_blueprint(self, blueprint: "Blueprint", **options: t.Any) -> None:blueprint.register(self, options)
    def iter_blueprints(self) -> t.ValuesView["Blueprint"]:return self.blueprints.values()
    @setupmethod
    def add_url_rule(
        self,
        rule: str,
        endpoint: t.Optional[str] = None,
        view_func: t.Optional[ft.RouteCallable] = None,
        provide_automatic_options: t.Optional[bool] = None,
        **options: t.Any,
    ) -> None:
        if endpoint is None:
            endpoint = _endpoint_from_view_func(view_func) 
        options["endpoint"] = endpoint
        methods = options.pop("methods", None)
        if methods is None:
            methods = getattr(view_func, "methods", None) or ("GET",)
        if isinstance(methods, str):
            raise TypeError(
                "Allowed methods must be a list of strings, for"
                ' example: @app.route(..., methods=["POST"])'
            )
        methods = {item.upper() for item in methods}
        required_methods = set(getattr(view_func, "required_methods", ()))
        if provide_automatic_options is None:
            provide_automatic_options = getattr(
                view_func, "provide_automatic_options", None
            )

        if provide_automatic_options is None:
            if "OPTIONS" not in methods:
                provide_automatic_options = True
                required_methods.add("OPTIONS")
            else:
                provide_automatic_options = False
        methods |= required_methods

        rule = self.url_rule_class(rule, methods=methods, **options)
        rule.provide_automatic_options = provide_automatic_options 

        self.url_map.add(rule)
        if view_func is not None:
            old_func = self.view_functions.get(endpoint)
            if old_func is not None and old_func != view_func:
                raise AssertionError(
                    "View function mapping is overwriting an existing"
                    f" endpoint function: {endpoint}"
                )
            self.view_functions[endpoint] = view_func
    @setupmethod
    def template_filter(
        self, name: t.Optional[str] = None
    ) -> t.Callable[[T_template_filter], T_template_filter]:

        def decorator(f: T_template_filter) -> T_template_filter:
            self.add_template_filter(f, name=name)
            return f

        return decorator

    @setupmethod
    def add_template_filter(
        self, f: ft.TemplateFilterCallable, name: t.Optional[str] = None
    ) -> None:
        self.jinja_env.filters[name or f.__name__] = f

    @setupmethod
    def template_test(
        self, name: t.Optional[str] = None
    ) -> t.Callable[[T_template_test], T_template_test]:

        def decorator(f: T_template_test) -> T_template_test:
            self.add_template_test(f, name=name)
            return f

        return decorator

    @setupmethod
    def add_template_test(
        self, f: ft.TemplateTestCallable, name: t.Optional[str] = None
    ) -> None:
        self.jinja_env.tests[name or f.__name__] = f

    @setupmethod
    def template_global(
        self, name: t.Optional[str] = None
    ) -> t.Callable[[T_template_global], T_template_global]:
        def decorator(f: T_template_global) -> T_template_global:
            self.add_template_global(f, name=name)
            return f

        return decorator

    @setupmethod
    def add_template_global(
        self, f: ft.TemplateGlobalCallable, name: t.Optional[str] = None
    ) -> None:
        self.jinja_env.globals[name or f.__name__] = f

    @setupmethod
    def before_first_request(self, f: T_before_first_request) -> T_before_first_request:
        

        warnings.warn(
            "'before_first_request' is deprecated and will be removed"
            " in Flask 2.3. Run setup code while creating the"
            " application instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.before_first_request_funcs.append(f)
        return f

    @setupmethod
    def teardown_appcontext(self, f: T_teardown) -> T_teardown:
        self.teardown_appcontext_funcs.append(f)
        return f

    @setupmethod
    def shell_context_processor(
        self, f: T_shell_context_processor
    ) -> T_shell_context_processor:
        self.shell_context_processors.append(f)
        return f

    def _find_error_handler(self, e: Exception) -> t.Optional[ft.ErrorHandlerCallable]:
        exc_class, code = self._get_exc_class_and_code(type(e))
        names = (*request.blueprints, None)

        for c in (code, None) if code is not None else (None,):
            for name in names:
                handler_map = self.error_handler_spec[name][c]

                if not handler_map:
                    continue

                for cls in exc_class.__mro__:
                    handler = handler_map.get(cls)

                    if handler is not None:
                        return handler
        return None

    def handle_http_exception(
        self, e: HTTPException
    ) -> t.Union[HTTPException, ft.ResponseReturnValue]:
        if e.code is None:
            return e
        if isinstance(e, RoutingException):
            return e

        handler = self._find_error_handler(e)
        if handler is None:
            return e
        return self.ensure_sync(handler)(e)

    def trap_http_exception(self, e: Exception) -> bool:
        if self.config["TRAP_HTTP_EXCEPTIONS"]:
            return True

        trap_bad_request = self.config["TRAP_BAD_REQUEST_ERRORS"]

        if (
            trap_bad_request is None
            and self.debug
            and isinstance(e, BadRequestKeyError)
        ):
            return True

        if trap_bad_request:
            return isinstance(e, BadRequest)

        return False

    def handle_user_exception(
        self, e: Exception
    ) -> t.Union[HTTPException, ft.ResponseReturnValue]:
        if isinstance(e, BadRequestKeyError) and (
            self.debug or self.config["TRAP_BAD_REQUEST_ERRORS"]
        ):
            e.show_exception = True

        if isinstance(e, HTTPException) and not self.trap_http_exception(e):
            return self.handle_http_exception(e)

        handler = self._find_error_handler(e)

        if handler is None:
            raise

        return self.ensure_sync(handler)(e)

    def handle_exception(self, e: Exception) -> Response:
        exc_info = sys.exc_info()
        got_request_exception.send(self, exception=e)
        propagate = self.config["PROPAGATE_EXCEPTIONS"]

        if propagate is None:
            propagate = self.testing or self.debug

        if propagate:
            if exc_info[1] is e:
                raise

            raise e

        self.log_exception(exc_info)
        server_error: t.Union[InternalServerError, ft.ResponseReturnValue]
        server_error = InternalServerError(original_exception=e)
        handler = self._find_error_handler(server_error)

        if handler is not None:
            server_error = self.ensure_sync(handler)(server_error)

        return self.finalize_request(server_error, from_error_handler=True)

    def log_exception(
        self,
        exc_info: t.Union[
            t.Tuple[type, BaseException, TracebackType], t.Tuple[None, None, None]
        ],
    ) -> None:
        self.logger.error(
            f"Exception on {request.path} [{request.method}]", exc_info=exc_info
        )

    def raise_routing_exception(self, request: Request) -> "te.NoReturn":
        if (
            not self.debug
            or not isinstance(request.routing_exception, RequestRedirect)
            or request.routing_exception.code in {307, 308}
            or request.method in {"GET", "HEAD", "OPTIONS"}
        ):
            raise request.routing_exception 

        raise FormDataRoutingRedirect(request)

    def dispatch_request(self) -> ft.ResponseReturnValue:
        req = request_ctx.request
        if req.routing_exception is not None:
            self.raise_routing_exception(req)
        rule: Rule = req.url_rule 
        if (
            getattr(rule, "provide_automatic_options", False)
            and req.method == "OPTIONS"
        ):
            return self.make_default_options_response()
        view_args: t.Dict[str, t.Any] = req.view_args 
        return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)

    def full_dispatch_request(self) -> Response:
        if not self._got_first_request:
            with self._before_request_lock:
                if not self._got_first_request:
                    for func in self.before_first_request_funcs:
                        self.ensure_sync(func)()

                    self._got_first_request = True

        try:
            request_started.send(self)
            rv = self.preprocess_request()
            if rv is None:
                rv = self.dispatch_request()
        except Exception as e:
            rv = self.handle_user_exception(e)
        return self.finalize_request(rv)

    def finalize_request(
        self,
        rv: t.Union[ft.ResponseReturnValue, HTTPException],
        from_error_handler: bool = False,
    ) -> Response:
        response = self.make_response(rv)
        try:
            response = self.process_response(response)
            request_finished.send(self, response=response)
        except Exception:
            if not from_error_handler:
                raise
            self.logger.exception(
                "Request finalizing failed with an error while handling an error"
            )
        return response

    def make_default_options_response(self) -> Response:
        adapter = request_ctx.url_adapter
        methods = adapter.allowed_methods()
        rv = self.response_class()
        rv.allow.update(methods)
        return rv

    def should_ignore_error(self, error: t.Optional[BaseException]) -> bool:
        return False

    def ensure_sync(self, func: t.Callable) -> t.Callable:
        if iscoroutinefunction(func):
            return self.async_to_sync(func)

        return func

    def async_to_sync(self, func: t.Callable[..., t.Coroutine]) -> t.Callable[..., t.Any]:
        try:
            from asgiref.sync import async_to_sync as asgiref_async_to_sync
        except ImportError:
            raise RuntimeError("Install Flask with the 'async' extra in order to use async views.") from None
        finally:
            return asgiref_async_to_sync(func)

    def url_for(
        self,
        endpoint: str,
        *,
        _anchor: t.Optional[str] = None,
        _method: t.Optional[str] = None,
        _scheme: t.Optional[str] = None,
        _external: t.Optional[bool] = None,
        **values: t.Any,
    ) -> str:
        req_ctx = _cv_request.get(None)

        if req_ctx is not None:
            url_adapter = req_ctx.url_adapter
            blueprint_name = req_ctx.request.blueprint
            if endpoint[:1] == ".":
                if blueprint_name is not None:
                    endpoint = f"{blueprint_name}{endpoint}"
                else:
                    endpoint = endpoint[1:]
            if _external is None:
                _external = _scheme is not None
        else:
            app_ctx = _cv_app.get(None)
            if app_ctx is not None:
                url_adapter = app_ctx.url_adapter
            else:
                url_adapter = self.create_url_adapter(None)

            if url_adapter is None:
                raise RuntimeError(
                    "Unable to build URLs outside an active request"
                    " without 'SERVER_NAME' configured. Also configure"
                    " 'APPLICATION_ROOT' and 'PREFERRED_URL_SCHEME' as"
                    " needed."
                )
            if _external is None:
                _external = True
        if _scheme is not None and not _external:
            raise ValueError("When specifying '_scheme', '_external' must be True.")

        self.inject_url_defaults(endpoint, values)

        try:
            rv = url_adapter.build(  
                endpoint,
                values,
                method=_method,
                url_scheme=_scheme,
                force_external=_external,
            )
        except BuildError as error:
            values.update(
                _anchor=_anchor, _method=_method, _scheme=_scheme, _external=_external
            )
            return self.handle_url_build_error(error, endpoint, values)

        if _anchor is not None:
            rv = f"{rv}#{url_quote(_anchor)}"

        return rv

    def redirect(self, location: str, code: int = 302) -> BaseResponse:
        return _wz_redirect(location, code=code, Response=self.response_class)

    def make_response(self, rv: ft.ResponseReturnValue) -> Response:

        status = headers = None
        if isinstance(rv, tuple):
            len_rv = len(rv)
            if len_rv == 3:
                rv, status, headers = rv 
            elif len_rv == 2:
                if isinstance(rv[1], (Headers, dict, tuple, list)):
                    rv, headers = rv
                else:
                    rv, status = rv 
            else:
                raise TypeError(
                    "The view function did not return a valid response tuple."
                    " The tuple must have the form (body, status, headers),"
                    " (body, status), or (body, headers)."
                )
        if rv is None:
            raise TypeError(
                f"The view function for {request.endpoint!r} did not"
                " return a valid response. The function either returned"
                " None or ended without a return statement."
            )
        if not isinstance(rv, self.response_class):
            if isinstance(rv, (str, bytes, bytearray)) or isinstance(rv, _abc_Iterator):
                rv = self.response_class(
                    rv,
                    status=status,
                    headers=headers,  
                )
                status = headers = None
            elif isinstance(rv, (dict, list)):
                rv = self.json.response(rv)
            elif isinstance(rv, BaseResponse) or callable(rv):
                try:
                    rv = self.response_class.force_type(
                        rv, request.environ
                    )
                except TypeError as e:
                    raise TypeError(
                        f"{e}\nThe view function did not return a valid"
                        " response. The return type must be a string,"
                        " dict, list, tuple with headers or status,"
                        " Response instance, or WSGI callable, but it"
                        f" was a {type(rv).__name__}."
                    ).with_traceback(sys.exc_info()[2]) from None
            else:
                raise TypeError(
                    "The view function did not return a valid"
                    " response. The return type must be a string,"
                    " dict, list, tuple with headers or status,"
                    " Response instance, or WSGI callable, but it was a"
                    f" {type(rv).__name__}."
                )

        rv = t.cast(Response, rv)
        if status is not None:
            if isinstance(status, (str, bytes, bytearray)):
                rv.status = status
            else:
                rv.status_code = status
        if headers:
            rv.headers.update(headers)  

        return rv

    def create_url_adapter(
        self, request: t.Optional[Request]
    ) -> t.Optional[MapAdapter]:
        if request is not None:
            if not self.subdomain_matching:
                subdomain = self.url_map.default_subdomain or None
            else:
                subdomain = None

            return self.url_map.bind_to_environ(
                request.environ,
                server_name=self.config["SERVER_NAME"],
                subdomain=subdomain,
            )
        if self.config["SERVER_NAME"] is not None:
            return self.url_map.bind(
                self.config["SERVER_NAME"],
                script_name=self.config["APPLICATION_ROOT"],
                url_scheme=self.config["PREFERRED_URL_SCHEME"],
            )

        return None

    def inject_url_defaults(self, endpoint: str, values: dict) -> None:
        names: t.Iterable[t.Optional[str]] = (None,)
        if "." in endpoint:
            names = chain(
                names, reversed(_split_blueprint_path(endpoint.rpartition(".")[0]))
            )

        for name in names:
            if name in self.url_default_functions:
                for func in self.url_default_functions[name]:
                    func(endpoint, values)

    def handle_url_build_error(
        self, error: BuildError, endpoint: str, values: t.Dict[str, t.Any]
    ) -> str:
        for handler in self.url_build_error_handlers:
            try:
                rv = handler(error, endpoint, values)
            except BuildError as e:
                error = e
            else:
                if rv is not None:
                    return rv
        if error is sys.exc_info()[1]:
            raise

        raise error

    def preprocess_request(self) -> t.Optional[ft.ResponseReturnValue]:
        names = (None, *reversed(request.blueprints))

        for name in names:
            if name in self.url_value_preprocessors:
                for url_func in self.url_value_preprocessors[name]:
                    url_func(request.endpoint, request.view_args)

        for name in names:
            if name in self.before_request_funcs:
                for before_func in self.before_request_funcs[name]:
                    rv = self.ensure_sync(before_func)()

                    if rv is not None:
                        return rv

        return None

    def process_response(self, response: Response) -> Response:
        ctx = request_ctx._get_current_object() 

        for func in ctx._after_request_functions:
            response = self.ensure_sync(func)(response)

        for name in chain(request.blueprints, (None,)):
            if name in self.after_request_funcs:
                for func in reversed(self.after_request_funcs[name]):
                    response = self.ensure_sync(func)(response)

        if not self.session_interface.is_null_session(ctx.session):
            self.session_interface.save_session(self, ctx.session, response)

        return response

    def do_teardown_request(
        self, exc: t.Optional[BaseException] = _sentinel 
    ) -> None:
        if exc is _sentinel:
            exc = sys.exc_info()[1]

        for name in chain(request.blueprints, (None,)):
            if name in self.teardown_request_funcs:
                for func in reversed(self.teardown_request_funcs[name]):
                    self.ensure_sync(func)(exc)

        request_tearing_down.send(self, exc=exc)

    def do_teardown_appcontext(
        self, exc: t.Optional[BaseException] = _sentinel 
    ) -> None:
        if exc is _sentinel:
            exc = sys.exc_info()[1]

        for func in reversed(self.teardown_appcontext_funcs):
            self.ensure_sync(func)(exc)

        appcontext_tearing_down.send(self, exc=exc)

    def app_context(self) -> AppContext:
        return AppContext(self)

    def request_context(self, environ: dict) -> RequestContext:
        return RequestContext(self, environ)
    def test_request_context(self, *args: t.Any, **kwargs: t.Any) -> RequestContext:
        builder = EnvironBuilder(self, *args, **kwargs)
        try:
            return self.request_context(builder.get_environ())
        finally:
            builder.close()
    def wsgi_app(self, environ: dict, start_response: t.Callable) -> t.Any:
        ctx = self.request_context(environ)
        error: t.Optional[BaseException] = None
        try:
            try:
                ctx.push()
                response = self.full_dispatch_request()
            except Exception as e:
                error = e
                response = self.handle_exception(e)
            except: 
                error = sys.exc_info()[1]
                raise
            return response(environ, start_response)
        finally:
            if "werkzeug.debug.preserve_context" in environ:
                environ["werkzeug.debug.preserve_context"](_cv_app.get())
                environ["werkzeug.debug.preserve_context"](_cv_request.get())
            if error is not None and self.should_ignore_error(error):error = None
            ctx.pop(error)
    def __call__(self, environ: dict, start_response: t.Callable) -> t.Any:return self.wsgi_app(environ, start_response)