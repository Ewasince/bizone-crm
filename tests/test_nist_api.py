from unittest import TestCase

from api.nist_api.nist_api import NistApi


class TestNistApi(TestCase):

    def setUp(self) -> None:
        pass

    def test_recursive_queries(self):
        # prepare

        nist_api = NistApi()

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
