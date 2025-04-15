#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import hashlib
import os
import tempfile
from typing import Any, Dict, Optional

from requests import Response


class Evidence(Dict[str, Any]):
    request_file_name: Optional[str] = None
    response_file_name: Optional[str] = None

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
            if (
                super().get("request_id", None) is None
                and super().get("request", None) is not None
            ):
                req = self.request.encode("utf-8")
                req_id = hashlib.blake2b(req, digest_size=16).hexdigest()
                self["request_id"] = req_id
        elif key == "response_id":
            if (
                super().get("response_id", None) is None
                and super().get("response", None) is not None
            ):
                res = self.response.encode("utf-8")
                res_id = hashlib.blake2b(res, digest_size=16).hexdigest()
                self["response_id"] = res_id

        # if the request or response is a file, we need to read it
        # we'll just return the contents of the file
        if key == "request" and self.request_file_name is not None:
            try:
                with open(self.request_file_name, "r") as req_file:
                    return req_file.read()
            except OSError:
                pass
        elif key == "response" and self.response_file_name is not None:
            try:
                with open(self.response_file_name, "r") as res_file:
                    return res_file.read()
            except OSError:
                pass

        return super().__getitem__(key)

    def __hash__(self):
        # return the hash of the entire object
        return hash(tuple(self.items()))

    def __eq__(self, other):
        if isinstance(other, Evidence):
            # check if the items are the same
            if len(self) != len(other):
                return False

            for k, v in self.items():
                if k not in other:
                    return False
                if v != other[k]:
                    return False

            return True
        else:
            return False

    @property
    def request(self) -> Optional[str]:
        if self.request_file_name is not None:
            try:
                with open(self.request_file_name, "r") as req_file:
                    return req_file.read()
            except OSError:
                pass
        else:
            return self.get("request", None)

    @property
    def response(self) -> Optional[str]:
        if self.response_file_name is not None:
            try:
                with open(self.response_file_name, "r") as res_file:
                    return res_file.read()
            except OSError:
                pass
        else:
            return self.get("response", None)

    @property
    def url(self) -> str:
        return self.get("url")

    @property
    def request_id(self) -> Optional[str]:
        return self.get("request_id", None)

    @property
    def response_id(self) -> Optional[str]:
        return self.get("response_id", None)

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

        min_cache_size = 1024 * 25  # 25kb

        if self.request is not None and len(self.request) > min_cache_size:
            with tempfile.NamedTemporaryFile(delete=False) as req_file:
                req_file.write(self.request.encode("utf-8"))
                self["request"] = ""
                self.request_file_name = req_file.name

        if self.response is not None and len(self.response) > min_cache_size:
            with tempfile.NamedTemporaryFile(delete=False) as res_file:
                res_file.write(self.response.encode("utf-8"))
                self["response"] = ""
                self.response_file_name = res_file.name

    def purge_files(self):
        # delete the temp files, if they exist
        if self.request_file_name is not None:
            try:
                os.remove(self.request_file_name)
            except OSError:
                pass
            self.request_file_name = None

        if self.response_file_name is not None:
            try:
                os.remove(self.response_file_name)
            except OSError:
                pass
            self.response_file_name = None
