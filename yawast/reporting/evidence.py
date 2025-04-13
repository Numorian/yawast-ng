#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import Optional, Any, Dict
from requests import Response

import hashlib, tempfile, os


class Evidence(Dict[str, Any]):
    request_file_name: Optional[str]
    response_file_name: Optional[str]

    def __init__(
        self,
        url: str,
        request: Optional[str],
        response: Optional[str],
        custom: Optional[Dict[str, Any]] = None,
    ):
        dict.__init__(self, url=url, request=request, response=response)
        if custom is not None:
            dict.update(self, custom)

        if request is not None:
            req = request.encode("utf-8")
            req_id = hashlib.blake2b(req, digest_size=16).hexdigest()
            dict.update(self, {"request_id": req_id})

        if response is not None:
            res = response.encode("utf-8")
            res_id = hashlib.blake2b(res, digest_size=16).hexdigest()
            dict.update(self, {"response_id": res_id})

    def __getitem__(self, key):
        # if request_id or response_id is accessed, we will need to make sure
        # that they are set, or set them instead just returning an error when accessed
        if key == "request_id":
            if not hasattr(self, "request_id") and super()["request"] is not None:
                req = self.request.encode("utf-8")
                req_id = hashlib.blake2b(req, digest_size=16).hexdigest()
                self.request_id = req_id
        elif key == "response_id":
            if not hasattr(self, "response_id") and super()["response"] is not None:
                res = self.response.encode("utf-8")
                res_id = hashlib.blake2b(res, digest_size=16).hexdigest()
                self.response_id = res_id

        # if the request or response is a file, we need to read it
        # we'll just return the contents of the file
        if key == "request" and hasattr(self, "request_file_name"):
            try:
                with open(self.request_file_name, "r") as req_file:
                    return req_file.read()
            except OSError:
                pass
        elif key == "response" and hasattr(self, "response_file_name"):
            try:
                with open(self.response_file_name, "r") as res_file:
                    return res_file.read()
            except OSError:
                pass

        return super().__getitem__(key)

    def __hash__(self):
        if self.request_id is not None and self.response_id is not None:
            # if we have both, we can use them
            return hash((self.request_id, self.response_id))
        elif self.request_id is not None:
            # if we only have the request_id, use that
            return hash(self.request_id)
        elif self.response_id is not None:
            # if we only have the response_id, use that
            return hash(self.response_id)
        else:
            # if we have neither, just use the parent class hash
            return super().__hash__()

    @property
    def request(self) -> Optional[str]:
        return self.get("request")

    @property
    def response(self) -> Optional[str]:
        return self.get("response")

    @property
    def url(self) -> str:
        return self.get("url")

    @property
    def request_id(self) -> Optional[str]:
        return self.get("request_id")

    @property
    def response_id(self) -> Optional[str]:
        return self.get("response_id")

    @property
    def custom(self) -> Optional[Dict[str, Any]]:
        return {
            k: v
            for k, v in self.items()
            if k not in ["url", "request", "response", "request_id", "response_id"]
        }

    @classmethod
    def from_response(cls, response: Response, custom: Optional[Dict[str, Any]] = None):
        from yawast.shared import network

        ev = cls(
            response.request.url,
            network.http_build_raw_request(response.request),
            network.http_build_raw_response(response),
            custom,
        )

        return ev

    def cache_to_file(self):
        # save the request and response to a file, if set
        # we save them as temp files, and we'll reload them when we need them

        min_cache_size = 1024 * 100  # 100kb

        if "request" in self and len(self["request"]) > min_cache_size:
            with tempfile.NamedTemporaryFile(delete=False) as req_file:
                req_file.write(self["request"].encode("utf-8"))
                self.request_file_name = req_file.name
                self["request"] = ""

        if "response" in self and len(self["response"]) > min_cache_size:
            with tempfile.NamedTemporaryFile(delete=False) as res_file:
                res_file.write(self["response"].encode("utf-8"))
                self.response_file_name = res_file.name
                self["response"] = ""

    def purge_files(self):
        # delete the temp files, if they exist
        if hasattr(self, "request_file_name") and self.request_file_name is not None:
            try:
                os.remove(self.request_file_name)
            except OSError:
                pass
            self.request_file_name = None

        if hasattr(self, "response_file_name") and self.response_file_name is not None:
            try:
                os.remove(self.response_file_name)
            except OSError:
                pass
            self.response_file_name = None
