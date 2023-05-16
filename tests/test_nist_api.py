from unittest import TestCase

from api.nist_api.nist_api import NistApi
from api.nist_api.enums import CvssSeverityV2Enum, CvssSeverityV3Enum


class TestNistApi(TestCase):

    def setUp(self) -> None:
        pass

    def test_recursive_queries(self):
        # prepare

        nist_api = NistApi.factory_method(None)

        test_list = [1, [2, 3], 4, [5, 6, 7]]

        # assert

        expected = [[1, 2, 4, 5],
                    [1, 2, 4, 6],
                    [1, 2, 4, 7],
                    [1, 3, 4, 5],
                    [1, 3, 4, 6],
                    [1, 3, 4, 7]]
        actual = nist_api.recursive_queries(test_list)

        self.assertEqual(expected, actual)

        pass

    def test_enum_cvss_2(self):
        # prepare
        class_to_test = CvssSeverityV2Enum

        # assert
        expected = ['LOW', 'MEDIUM', 'HIGH']

        actual = class_to_test.get_values()

        self.assertEqual(expected, actual)

        pass

    def test_enum_cvss_3(self):
        # prepare
        class_to_test = CvssSeverityV3Enum

        # assert
        expected = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

        actual = class_to_test.get_values()

        self.assertEqual(expected, actual)

        pass
