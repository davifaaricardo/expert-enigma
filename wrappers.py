import typing as t

from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Request as RequestBase
from werkzeug.wrappers import Response as ResponseBase

from . import json
from .globals import current_app
from .helpers import _split_blueprint_path

if t.TYPE_CHECKING:  # pragma: no cover
    from werkzeug.routing import Rule


class Request(RequestBase):
    json_module = json
    url_rule: t.Optional["Rule"] = None
    view_args: t.Optional[t.Dict[str, t.Any]] = None

    routing_exception: t.Optional[Exception] = None

    @property
    def max_content_length(self) -> t.Optional[int]:
        if current_app:
            return current_app.config["MAX_CONTENT_LENGTH"]
        else:
            return None

    @property
    def endpoint(self) -> t.Optional[str]:

        if self.url_rule is not None:
            return self.url_rule.endpoint

        return None

    @property
    def blueprint(self) -> t.Optional[str]:
        endpoint = self.endpoint

        if endpoint is not None and "." in endpoint:
            return endpoint.rpartition(".")[0]

        return None

    @property
    def blueprints(self) -> t.List[str]:
        name = self.blueprint

        if name is None:
            return []

        return _split_blueprint_path(name)

    def _load_form_data(self) -> None:
        super()._load_form_data()
        if (
            current_app
            and current_app.debug
            and self.mimetype != "multipart/form-data"
            and not self.files
        ):
            from ..debughelpers import attach_enctype_error_multidict

            attach_enctype_error_multidict(self)

    def on_json_loading_failed(self, e: t.Optional[ValueError]) -> t.Any:
        try:
            return super().on_json_loading_failed(e)
        except BadRequest as e:
            if current_app and current_app.debug:
                raise

            raise BadRequest() from e


class Response(ResponseBase):
    """The response object that is used by default in Flask.  Works like the
    response object from Werkzeug but is set to have an HTML mimetype by
    default.  Quite often you don't have to create this object yourself because
    :meth:`~flask.Flask.make_response` will take care of that for you.

    If you want to replace the response object used you can subclass this and
    set :attr:`~flask.Flask.response_class` to your subclass.

    .. versionchanged:: 1.0
        JSON support is added to the response, like the request. This is useful
        when testing to get the test client response data as JSON.

    .. versionchanged:: 1.0

        Added :attr:`max_cookie_size`.
    """

    default_mimetype = "text/html"

    json_module = json

    autocorrect_location_header = False

    @property
    def max_cookie_size(self) -> int:  # type: ignore
        """Read-only view of the :data:`MAX_COOKIE_SIZE` config key.

        See :attr:`~werkzeug.wrappers.Response.max_cookie_size` in
        Werkzeug's docs.
        """
        if current_app:
            return current_app.config["MAX_COOKIE_SIZE"]

        # return Werkzeug's default when not in an app context
        return super().max_cookie_size
