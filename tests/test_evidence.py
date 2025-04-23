import hashlib
import os
import tempfile
from typing import Any, Dict, cast
from unittest.mock import Mock, patch

import pytest
from requests import PreparedRequest, Response

from yawast.reporting.evidence import Evidence


class TestEvidenceInit:
    def test_init_with_url_only(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        assert evidence["url"] == url
        assert evidence.get("request") is None
        assert evidence.get("response") is None
        assert evidence.get("request_id") is None
        assert evidence.get("response_id") is None

    def test_init_with_request(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, request, None)

        assert evidence["url"] == url
        assert evidence["request"] == request
        assert evidence.get("request_id") is not None
        assert evidence.get("response") is None
        assert evidence.get("response_id") is None

    def test_init_with_response(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response)

        assert evidence["url"] == url
        assert evidence["response"] == response
        assert evidence.get("response_id") is not None
        assert evidence.get("request") is None
        assert evidence.get("request_id") is None

    def test_init_with_request_and_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        assert evidence["url"] == url
        assert evidence["request"] == request
        assert evidence["response"] == response
        assert evidence.get("request_id") is not None
        assert evidence.get("response_id") is not None

    def test_init_with_custom_data(self):
        url = "http://example.com"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, None, None, custom=custom_data)

        assert evidence["url"] == url
        assert evidence["key1"] == "value1"
        assert evidence["key2"] == "value2"
        assert evidence.get("request") is None
        assert evidence.get("response") is None
        assert evidence.get("request_id") is None
        assert evidence.get("response_id") is None


class TestEvidenceGetItem:
    def test_getitem_request_id_generated(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, request, None)

        # Accessing request_id should generate it
        request_id = evidence["request_id"]
        assert request_id is not None
        assert (
            request_id
            == hashlib.blake2b(request.encode("utf-8"), digest_size=16).hexdigest()
        )

    def test_getitem_response_id_generated(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response)

        # Accessing response_id should generate it
        response_id = evidence["response_id"]
        assert response_id is not None
        assert (
            response_id
            == hashlib.blake2b(response.encode("utf-8"), digest_size=16).hexdigest()
        )

    def test_getitem_request_id_late_set(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        evidence["request"] = request

        # Accessing request_id should generate it
        request_id = evidence["request_id"]
        assert request_id is not None
        assert (
            request_id
            == hashlib.blake2b(request.encode("utf-8"), digest_size=16).hexdigest()
        )

    def test_getitem_response_id_late_set(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)
        evidence["response"] = response

        # Accessing response_id should generate it
        response_id = evidence["response_id"]
        assert response_id is not None
        assert (
            response_id
            == hashlib.blake2b(response.encode("utf-8"), digest_size=16).hexdigest()
        )

    def test_getitem_request_from_file(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(request_content)
            evidence.request_file_name = temp_file.name

        # Accessing request should read from the file
        assert evidence["request"] == request_content

        # Clean up
        os.remove(temp_file.name)

    def test_getitem_response_from_file(self):
        url = "http://example.com"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(response_content)
            evidence.response_file_name = temp_file.name

        # Accessing response should read from the file
        assert evidence["response"] == response_content

        # Clean up
        os.remove(temp_file.name)

    def test_getitem_key_not_found(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        with pytest.raises(KeyError):
            _ = evidence["non_existent_key"]


class TestEvidenceHash:
    def test_hash_with_identical_objects(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request, response)
        evidence2 = Evidence(url, request, response)

        # Hashes of identical objects should be the same
        assert hash(evidence1) == hash(evidence2)

    def test_hash_with_different_objects(self):
        url1 = "http://example.com"
        url2 = "http://example.org"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url1, request, response)
        evidence2 = Evidence(url2, request, response)

        # Hashes of different objects should not be the same
        assert hash(evidence1) != hash(evidence2)

    def test_hash_with_custom_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data1 = {"key1": "value1"}
        custom_data2 = {"key1": "value2"}
        evidence1 = Evidence(url, request, response, custom=custom_data1)
        evidence2 = Evidence(url, request, response, custom=custom_data2)

        # Hashes should differ if custom data is different
        assert hash(evidence1) != hash(evidence2)

    def test_hash_with_empty_object(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Hash should be consistent for an empty object
        assert isinstance(hash(evidence), int)


class TestEvidenceEquality:
    def test_eq_with_identical_objects(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request, response)
        evidence2 = Evidence(url, request, response)

        # Identical objects should be equal
        assert evidence1 == evidence2

    def test_eq_with_different_urls(self):
        url1 = "http://example.com"
        url2 = "http://example.org"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url1, request, response)
        evidence2 = Evidence(url2, request, response)

        # Objects with different URLs should not be equal
        assert evidence1 != evidence2

    def test_eq_with_different_requests(self):
        url = "http://example.com"
        request1 = "GET / HTTP/1.1"
        request2 = "POST / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request1, response)
        evidence2 = Evidence(url, request2, response)

        # Objects with different requests should not be equal
        assert evidence1 != evidence2

    def test_eq_with_different_responses(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response1 = "HTTP/1.1 200 OK"
        response2 = "HTTP/1.1 404 Not Found"
        evidence1 = Evidence(url, request, response1)
        evidence2 = Evidence(url, request, response2)

        # Objects with different responses should not be equal
        assert evidence1 != evidence2

    def test_eq_with_different_custom_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data1 = {"key1": "value1"}
        custom_data2 = {"key1": "value2"}
        evidence1 = Evidence(url, request, response, custom=custom_data1)
        evidence2 = Evidence(url, request, response, custom=custom_data2)

        # Objects with different custom data should not be equal
        assert evidence1 != evidence2

    def test_eq_with_non_evidence_object(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Comparing with a non-Evidence object should return False
        assert evidence != {"url": url, "request": request, "response": response}

    def test_eq_with_empty_objects(self):
        url = "http://example.com"
        evidence1 = Evidence(url, None, None)
        evidence2 = Evidence(url, None, None)

        # Empty objects with the same URL should be equal
        assert evidence1 == evidence2

    def test_eq_with_different_lengths(self):
        url = "http://example.com"
        evidence1 = Evidence(url, None, None)
        evidence2 = Evidence(url, None, None, custom={"key": "value"})

        # Objects with different lengths should not be equal
        assert evidence1 != evidence2


class TestEvidenceRequestProperty:
    def test_request_property_with_direct_value(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, request_content, None)

        # The request property should return the direct value
        assert evidence.request == request_content

    def test_request_property_with_file(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(request_content)
            evidence.request_file_name = temp_file.name

        # The request property should read from the file
        assert evidence.request == request_content

        # Clean up
        os.remove(temp_file.name)

    def test_request_property_with_missing_file(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)
        evidence.request_file_name = "non_existent_file.txt"

        # The request property should return None if the file is missing
        assert evidence.request is None

    def test_request_property_with_no_value(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The request property should return None if no value is set
        assert evidence.request is None


class TestEvidenceResponseProperty:
    def test_response_property_with_direct_value(self):
        url = "http://example.com"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response_content)

        # The response property should return the direct value
        assert evidence.response == response_content

    def test_response_property_with_file(self):
        url = "http://example.com"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(response_content)
            evidence.response_file_name = temp_file.name

        # The response property should read from the file
        assert evidence.response == response_content

        # Clean up
        os.remove(temp_file.name)

    def test_response_property_with_missing_file(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)
        evidence.response_file_name = "non_existent_file.txt"

        # The response property should return None if the file is missing
        assert evidence.response is None

    def test_response_property_with_no_value(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The response property should return None if no value is set
        assert evidence.response is None


class TestEvidenceCustomProperty:
    def test_custom_property_with_no_custom_data(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The custom property should return an empty dictionary if no custom data is set
        assert evidence.custom == {}

    def test_custom_property_with_custom_data(self):
        url = "http://example.com"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, None, None, custom=custom_data)

        # The custom property should return the custom data
        assert evidence.custom == custom_data

    def test_custom_property_with_mixed_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, request, response, custom=custom_data)

        # The custom property should exclude standard keys and return only custom data
        assert evidence.custom == custom_data

    def test_custom_property_with_overlapping_keys(self):
        url = "http://example.com"
        custom_data = {"url": "http://other.com", "key1": "value1"}
        evidence = Evidence(url, None, None, custom=custom_data)

        # The custom property should exclude standard keys like "url"
        assert evidence.custom == {"key1": "value1"}


class TestEvidenceFromResponse:
    @patch("yawast.shared.network.http_build_raw_request")
    @patch("yawast.shared.network.http_build_raw_response")
    def test_from_response_with_valid_response(
        self, mock_http_build_raw_response, mock_http_build_raw_request
    ):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        response_content = "HTTP/1.1 200 OK"
        custom_data = {"key1": "value1"}

        # Mock the Response object
        mock_response = Mock(spec=Response)
        mock_response.request = Mock(spec=PreparedRequest)
        mock_response.request.url = url
        mock_http_build_raw_request.return_value = request_content
        mock_http_build_raw_response.return_value = response_content

        # Call the from_response method
        evidence = Evidence.from_response(mock_response, custom=custom_data)

        # Assertions
        assert evidence["url"] == url
        assert evidence["request"] == request_content
        assert evidence["response"] == response_content
        assert evidence["key1"] == "value1"
        assert evidence["request_id"] is not None
        assert evidence["response_id"] is not None

        # Verify mocks
        mock_http_build_raw_request.assert_called_once_with(mock_response.request)
        mock_http_build_raw_response.assert_called_once_with(mock_response)

    @patch("yawast.shared.network.http_build_raw_request")
    @patch("yawast.shared.network.http_build_raw_response")
    def test_from_response_with_no_custom_data(
        self, mock_http_build_raw_response, mock_http_build_raw_request
    ):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        response_content = "HTTP/1.1 200 OK"

        # Mock the Response object
        mock_response = Mock(spec=Response)
        mock_response.request = Mock(spec=PreparedRequest)
        mock_response.request.url = url
        mock_http_build_raw_request.return_value = request_content
        mock_http_build_raw_response.return_value = response_content

        # Call the from_response method
        evidence = Evidence.from_response(mock_response)

        # Assertions
        assert evidence["url"] == url
        assert evidence["request"] == request_content
        assert evidence["response"] == response_content
        assert evidence["request_id"] is not None
        assert evidence["response_id"] is not None

        # Verify mocks
        mock_http_build_raw_request.assert_called_once_with(mock_response.request)
        mock_http_build_raw_response.assert_called_once_with(mock_response)

    @patch("yawast.shared.network.http_build_raw_request")
    @patch("yawast.shared.network.http_build_raw_response")
    def test_from_response_with_empty_response(
        self, mock_http_build_raw_response, mock_http_build_raw_request
    ):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"

        # Mock the Response object
        mock_response = Mock(spec=Response)
        mock_response.request = Mock(spec=PreparedRequest)
        mock_response.request.url = url
        mock_http_build_raw_request.return_value = request_content
        mock_http_build_raw_response.return_value = None

        # Call the from_response method
        evidence = Evidence.from_response(mock_response)

        # Assertions
        assert evidence["url"] == url
        assert evidence["request"] == request_content
        assert evidence["response"] is None
        assert evidence["request_id"] is not None
        assert evidence.get("response_id") is None

        # Verify mocks
        mock_http_build_raw_request.assert_called_once_with(mock_response.request)
        mock_http_build_raw_response.assert_called_once_with(mock_response)


class TestEvidenceCacheToFile:
    def test_cache_to_file_with_small_request_and_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure request and response are not cached to files
        assert evidence.request_file_name is None
        assert evidence.response_file_name is None
        assert evidence["request"] == request
        assert evidence["response"] == response

    def test_cache_to_file_with_large_request(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1\n" + "A" * (1024 * 30)  # 30KB request
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure request is cached to a file
        assert evidence.request_file_name is not None
        assert evidence.get("request") == ""

        # Ensure response is not cached to a file
        assert evidence.response_file_name is None
        assert evidence["response"] == response

        # Clean up
        if evidence.request_file_name:
            os.remove(evidence.request_file_name)

    def test_cache_to_file_with_large_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK\n" + "B" * (1024 * 30)  # 30KB response
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure response is cached to a file
        assert evidence.response_file_name is not None
        assert evidence.get("response") == ""

        # Ensure request is not cached to a file
        assert evidence.request_file_name is None
        assert evidence["request"] == request

        # Clean up
        if evidence.response_file_name:
            os.remove(evidence.response_file_name)

    def test_cache_to_file_with_large_request_and_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1\n" + "A" * (1024 * 30)  # 30KB request
        response = "HTTP/1.1 200 OK\n" + "B" * (1024 * 30)  # 30KB response
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure both request and response are cached to files
        assert evidence.request_file_name is not None
        assert evidence.response_file_name is not None
        assert evidence.get("request") == ""
        assert evidence.get("response") == ""

        # Clean up
        if evidence.request_file_name:
            os.remove(evidence.request_file_name)
        if evidence.response_file_name:
            os.remove(evidence.response_file_name)


class TestEvidencePurgeFiles:
    def test_purge_files_with_existing_files(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)

        # Create temporary files for request and response
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as req_file:
            req_file.write(request_content)
            evidence.request_file_name = req_file.name

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as res_file:
            res_file.write(response_content)
            evidence.response_file_name = res_file.name

        # Ensure files exist before calling purge_files
        assert os.path.exists(evidence.request_file_name)
        assert os.path.exists(evidence.response_file_name)

        res_file_name = evidence.response_file_name
        req_file_name = evidence.request_file_name

        # Call purge_files
        evidence.purge_files()

        # Ensure files are deleted and file names are set to None
        assert not os.path.exists(res_file_name)
        assert not os.path.exists(req_file_name)
        assert evidence.request_file_name is None
        assert evidence.response_file_name is None

    def test_purge_files_with_missing_files(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Set non-existent file names
        evidence.request_file_name = "non_existent_request.txt"
        evidence.response_file_name = "non_existent_response.txt"

        # Call purge_files
        evidence.purge_files()

        # Ensure file names are set to None
        assert evidence.request_file_name is None
        assert evidence.response_file_name is None

    def test_purge_files_with_no_files_set(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Ensure no file names are set initially
        assert evidence.request_file_name is None
        assert evidence.response_file_name is None

        # Call purge_files
        evidence.purge_files()

        # Ensure file names remain None
        assert evidence.request_file_name is None
        assert evidence.response_file_name is None


class TestEvidence:
    def test_evidence(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)
        assert evidence is not None


import os
import tempfile
from unittest import mock

from yawast.reporting.evidence import Evidence


def test_evidence_init_and_properties():
    ev = Evidence("http://foo", "req", "resp", {"x": 1})
    assert ev.url == "http://foo"
    assert ev.request == "req"
    assert ev.response == "resp"
    assert ev.custom["x"] == 1
    assert isinstance(ev.request_id, str)
    assert isinstance(ev.response_id, str)


def test_evidence_eq_and_hash():
    ev1 = Evidence("http://foo", "req", "resp", {"x": 1})
    ev2 = Evidence("http://foo", "req", "resp", {"x": 1})
    ev3 = Evidence("http://foo", "req2", "resp", {"x": 1})
    assert ev1 == ev2
    assert ev1 != ev3
    assert hash(ev1) == hash(ev2)


def test_evidence_getitem_and_file(monkeypatch, tmp_path):
    ev = Evidence("http://foo", "req", "resp")
    # Simulate file for request
    req_file = tmp_path / "req.txt"
    req_file.write_text("file_req")
    ev.request_file_name = str(req_file)
    assert ev["request"] == "file_req"
    # Simulate file for response
    res_file = tmp_path / "res.txt"
    res_file.write_text("file_resp")
    ev.response_file_name = str(res_file)
    assert ev["response"] == "file_resp"


def test_evidence_from_response(monkeypatch):
    class DummyReq:
        url = "http://foo"

    class DummyResp:
        request = DummyReq()

    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_request", lambda req: "rawreq"
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda resp: "rawresp"
    )
    ev = Evidence.from_response(DummyResp())
    assert ev["request"] == "rawreq"
    assert ev["response"] == "rawresp"


def test_evidence_cache_to_file_and_purge(tmp_path):
    big = "x" * (1024 * 26)
    ev = Evidence("http://foo", big, big)
    ev.cache_to_file()
    assert ev.request_file_name is not None
    assert ev.response_file_name is not None
    assert os.path.exists(ev.request_file_name)
    assert os.path.exists(ev.response_file_name)
    ev.purge_files()
    assert ev.request_file_name is None
    assert ev.response_file_name is None
