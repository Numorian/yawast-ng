from typing import Optional, Any, Dict

from requests import Response

from yawast.shared import network


class Evidence(Dict[str, Any]):
    url: str
    request: Optional[str]
    response: Optional[str]
    custom: Optional[Dict[str, Any]]

    def __init__(
        self,
        url: str,
        request: Optional[str],
        response: Optional[str],
        custom: Optional[Dict[str, Any]] = None,
    ):
        self.url = url
        self.request = request
        self.response = response
        self.custom = custom

        dict.__init__(self, request=request, response=response)
        if custom is not None:
            dict.update(self, custom)

    @classmethod
    def from_response(cls, response: Response, custom: Optional[Dict[str, Any]] = None):
        ev = cls(
            response.request.url,
            network.http_build_raw_request(response.request),
            network.http_build_raw_response(response),
            custom,
        )

        return ev
