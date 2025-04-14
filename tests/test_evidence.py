import hashlib
import os
import tempfile
from typing import Any, Dict, cast
import unittest
from yawast.reporting.evidence import Evidence
from unittest.mock import Mock, patch
from requests import PreparedRequest, Response


class TestEvidenceInit(unittest.TestCase):
    def test_init_with_url_only(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        self.assertEqual(evidence["url"], url)
        self.assertIsNone(evidence.get("request"))
        self.assertIsNone(evidence.get("response"))
        self.assertIsNone(evidence.get("request_id"))
        self.assertIsNone(evidence.get("response_id"))

    def test_init_with_request(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, request, None)

        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["request"], request)
        self.assertIsNotNone(evidence.get("request_id"))
        self.assertIsNone(evidence.get("response"))
        self.assertIsNone(evidence.get("response_id"))

    def test_init_with_response(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response)

        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["response"], response)
        self.assertIsNotNone(evidence.get("response_id"))
        self.assertIsNone(evidence.get("request"))
        self.assertIsNone(evidence.get("request_id"))

    def test_init_with_request_and_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["request"], request)
        self.assertEqual(evidence["response"], response)
        self.assertIsNotNone(evidence.get("request_id"))
        self.assertIsNotNone(evidence.get("response_id"))

    def test_init_with_custom_data(self):
        url = "http://example.com"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, None, None, custom=custom_data)

        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["key1"], "value1")
        self.assertEqual(evidence["key2"], "value2")
        self.assertIsNone(evidence.get("request"))
        self.assertIsNone(evidence.get("response"))
        self.assertIsNone(evidence.get("request_id"))
        self.assertIsNone(evidence.get("response_id"))


class TestEvidenceGetItem(unittest.TestCase):
    def test_getitem_request_id_generated(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, request, None)

        # Accessing request_id should generate it
        request_id = evidence["request_id"]
        self.assertIsNotNone(request_id)
        self.assertEqual(
            request_id,
            hashlib.blake2b(request.encode("utf-8"), digest_size=16).hexdigest(),
        )

    def test_getitem_response_id_generated(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response)

        # Accessing response_id should generate it
        response_id = evidence["response_id"]
        self.assertIsNotNone(response_id)
        self.assertEqual(
            response_id,
            hashlib.blake2b(response.encode("utf-8"), digest_size=16).hexdigest(),
        )

    def test_getitem_request_id_late_set(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        evidence["request"] = request

        # Accessing request_id should generate it
        request_id = evidence["request_id"]
        self.assertIsNotNone(request_id)
        self.assertEqual(
            request_id,
            hashlib.blake2b(request.encode("utf-8"), digest_size=16).hexdigest(),
        )

    def test_getitem_response_id_late_set(self):
        url = "http://example.com"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)
        evidence["response"] = response

        # Accessing response_id should generate it
        response_id = evidence["response_id"]
        self.assertIsNotNone(response_id)
        self.assertEqual(
            response_id,
            hashlib.blake2b(response.encode("utf-8"), digest_size=16).hexdigest(),
        )

    def test_getitem_request_from_file(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(request_content)
            evidence.request_file_name = temp_file.name

        # Accessing request should read from the file
        self.assertEqual(evidence["request"], request_content)

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
        self.assertEqual(evidence["response"], response_content)

        # Clean up
        os.remove(temp_file.name)

    def test_getitem_key_not_found(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        with self.assertRaises(KeyError):
            _ = evidence["non_existent_key"]


class TestEvidenceHash(unittest.TestCase):
    def test_hash_with_identical_objects(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request, response)
        evidence2 = Evidence(url, request, response)

        # Hashes of identical objects should be the same
        self.assertEqual(hash(evidence1), hash(evidence2))

    def test_hash_with_different_objects(self):
        url1 = "http://example.com"
        url2 = "http://example.org"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url1, request, response)
        evidence2 = Evidence(url2, request, response)

        # Hashes of different objects should not be the same
        self.assertNotEqual(hash(evidence1), hash(evidence2))

    def test_hash_with_custom_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data1 = {"key1": "value1"}
        custom_data2 = {"key1": "value2"}
        evidence1 = Evidence(url, request, response, custom=custom_data1)
        evidence2 = Evidence(url, request, response, custom=custom_data2)

        # Hashes should differ if custom data is different
        self.assertNotEqual(hash(evidence1), hash(evidence2))

    def test_hash_with_empty_object(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Hash should be consistent for an empty object
        self.assertIsInstance(hash(evidence), int)


class TestEvidenceEquality(unittest.TestCase):
    def test_eq_with_identical_objects(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request, response)
        evidence2 = Evidence(url, request, response)

        # Identical objects should be equal
        self.assertEqual(evidence1, evidence2)

    def test_eq_with_different_urls(self):
        url1 = "http://example.com"
        url2 = "http://example.org"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url1, request, response)
        evidence2 = Evidence(url2, request, response)

        # Objects with different URLs should not be equal
        self.assertNotEqual(evidence1, evidence2)

    def test_eq_with_different_requests(self):
        url = "http://example.com"
        request1 = "GET / HTTP/1.1"
        request2 = "POST / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence1 = Evidence(url, request1, response)
        evidence2 = Evidence(url, request2, response)

        # Objects with different requests should not be equal
        self.assertNotEqual(evidence1, evidence2)

    def test_eq_with_different_responses(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response1 = "HTTP/1.1 200 OK"
        response2 = "HTTP/1.1 404 Not Found"
        evidence1 = Evidence(url, request, response1)
        evidence2 = Evidence(url, request, response2)

        # Objects with different responses should not be equal
        self.assertNotEqual(evidence1, evidence2)

    def test_eq_with_different_custom_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data1 = {"key1": "value1"}
        custom_data2 = {"key1": "value2"}
        evidence1 = Evidence(url, request, response, custom=custom_data1)
        evidence2 = Evidence(url, request, response, custom=custom_data2)

        # Objects with different custom data should not be equal
        self.assertNotEqual(evidence1, evidence2)

    def test_eq_with_non_evidence_object(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Comparing with a non-Evidence object should return False
        self.assertNotEqual(
            evidence, {"url": url, "request": request, "response": response}
        )

    def test_eq_with_empty_objects(self):
        url = "http://example.com"
        evidence1 = Evidence(url, None, None)
        evidence2 = Evidence(url, None, None)

        # Empty objects with the same URL should be equal
        self.assertEqual(evidence1, evidence2)

    def test_eq_with_different_lengths(self):
        url = "http://example.com"
        evidence1 = Evidence(url, None, None)
        evidence2 = Evidence(url, None, None, custom={"key": "value"})

        # Objects with different lengths should not be equal
        self.assertNotEqual(evidence1, evidence2)


class TestEvidenceRequestProperty(unittest.TestCase):
    def test_request_property_with_direct_value(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, request_content, None)

        # The request property should return the direct value
        self.assertEqual(evidence.request, request_content)

    def test_request_property_with_file(self):
        url = "http://example.com"
        request_content = "GET / HTTP/1.1"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(request_content)
            evidence.request_file_name = temp_file.name

        # The request property should read from the file
        self.assertEqual(evidence.request, request_content)

        # Clean up
        os.remove(temp_file.name)

    def test_request_property_with_missing_file(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)
        evidence.request_file_name = "non_existent_file.txt"

        # The request property should return None if the file is missing
        self.assertIsNone(evidence.request)

    def test_request_property_with_no_value(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The request property should return None if no value is set
        self.assertIsNone(evidence.request)


class TestEvidenceResponseProperty(unittest.TestCase):
    def test_response_property_with_direct_value(self):
        url = "http://example.com"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, response_content)

        # The response property should return the direct value
        self.assertEqual(evidence.response, response_content)

    def test_response_property_with_file(self):
        url = "http://example.com"
        response_content = "HTTP/1.1 200 OK"
        evidence = Evidence(url, None, None)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(response_content)
            evidence.response_file_name = temp_file.name

        # The response property should read from the file
        self.assertEqual(evidence.response, response_content)

        # Clean up
        os.remove(temp_file.name)

    def test_response_property_with_missing_file(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)
        evidence.response_file_name = "non_existent_file.txt"

        # The response property should return None if the file is missing
        self.assertIsNone(evidence.response)

    def test_response_property_with_no_value(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The response property should return None if no value is set
        self.assertIsNone(evidence.response)


class TestEvidenceCustomProperty(unittest.TestCase):
    def test_custom_property_with_no_custom_data(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # The custom property should return an empty dictionary if no custom data is set
        self.assertEqual(evidence.custom, {})

    def test_custom_property_with_custom_data(self):
        url = "http://example.com"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, None, None, custom=custom_data)

        # The custom property should return the custom data
        self.assertEqual(evidence.custom, custom_data)

    def test_custom_property_with_mixed_data(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        custom_data = {"key1": "value1", "key2": "value2"}
        evidence = Evidence(url, request, response, custom=custom_data)

        # The custom property should exclude standard keys and return only custom data
        self.assertEqual(evidence.custom, custom_data)

    def test_custom_property_with_overlapping_keys(self):
        url = "http://example.com"
        custom_data = {"url": "http://other.com", "key1": "value1"}
        evidence = Evidence(url, None, None, custom=custom_data)

        # The custom property should exclude standard keys like "url"
        self.assertEqual(evidence.custom, {"key1": "value1"})


class TestEvidenceFromResponse(unittest.TestCase):
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
        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["request"], request_content)
        self.assertEqual(evidence["response"], response_content)
        self.assertEqual(evidence["key1"], "value1")
        self.assertIsNotNone(evidence["request_id"])
        self.assertIsNotNone(evidence["response_id"])

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
        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["request"], request_content)
        self.assertEqual(evidence["response"], response_content)
        self.assertIsNotNone(evidence["request_id"])
        self.assertIsNotNone(evidence["response_id"])

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
        self.assertEqual(evidence["url"], url)
        self.assertEqual(evidence["request"], request_content)
        self.assertIsNone(evidence["response"])
        self.assertIsNotNone(evidence["request_id"])
        self.assertIsNone(evidence.get("response_id"))

        # Verify mocks
        mock_http_build_raw_request.assert_called_once_with(mock_response.request)
        mock_http_build_raw_response.assert_called_once_with(mock_response)


class TestEvidenceCacheToFile(unittest.TestCase):
    def test_cache_to_file_with_small_request_and_response(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1"
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure request and response are not cached to files
        self.assertIsNone(evidence.request_file_name)
        self.assertIsNone(evidence.response_file_name)
        self.assertEqual(evidence["request"], request)
        self.assertEqual(evidence["response"], response)

    def test_cache_to_file_with_large_request(self):
        url = "http://example.com"
        request = "GET / HTTP/1.1\n" + "A" * (1024 * 30)  # 30KB request
        response = "HTTP/1.1 200 OK"
        evidence = Evidence(url, request, response)

        # Call cache_to_file
        evidence.cache_to_file()

        # Ensure request is cached to a file
        self.assertIsNotNone(evidence.request_file_name)
        self.assertEqual(evidence.get("request"), "")

        # Ensure response is not cached to a file
        self.assertIsNone(evidence.response_file_name)
        self.assertEqual(evidence["response"], response)

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
        self.assertIsNotNone(evidence.response_file_name)
        self.assertEqual(evidence.get("response"), "")

        # Ensure request is not cached to a file
        self.assertIsNone(evidence.request_file_name)
        self.assertEqual(evidence["request"], request)

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
        self.assertIsNotNone(evidence.request_file_name)
        self.assertIsNotNone(evidence.response_file_name)
        self.assertEqual(evidence.get("request"), "")
        self.assertEqual(evidence.get("response"), "")

        # Clean up
        if evidence.request_file_name:
            os.remove(evidence.request_file_name)
        if evidence.response_file_name:
            os.remove(evidence.response_file_name)


class TestEvidencePurgeFiles(unittest.TestCase):
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
        self.assertTrue(os.path.exists(evidence.request_file_name))
        self.assertTrue(os.path.exists(evidence.response_file_name))

        res_file_name = evidence.response_file_name
        req_file_name = evidence.request_file_name

        # Call purge_files
        evidence.purge_files()

        # Ensure files are deleted and file names are set to None
        self.assertFalse(os.path.exists(res_file_name))
        self.assertFalse(os.path.exists(req_file_name))
        self.assertIsNone(evidence.request_file_name)
        self.assertIsNone(evidence.response_file_name)

    def test_purge_files_with_missing_files(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Set non-existent file names
        evidence.request_file_name = "non_existent_request.txt"
        evidence.response_file_name = "non_existent_response.txt"

        # Call purge_files
        evidence.purge_files()

        # Ensure file names are set to None
        self.assertIsNone(evidence.request_file_name)
        self.assertIsNone(evidence.response_file_name)

    def test_purge_files_with_no_files_set(self):
        url = "http://example.com"
        evidence = Evidence(url, None, None)

        # Ensure no file names are set initially
        self.assertIsNone(evidence.request_file_name)
        self.assertIsNone(evidence.response_file_name)

        # Call purge_files
        evidence.purge_files()

        # Ensure file names remain None
        self.assertIsNone(evidence.request_file_name)
        self.assertIsNone(evidence.response_file_name)
