from unittest import TestCase

from api.cve_builder.cve_builder import CveTupleBuilder, cve_tuple_fields, CveTuple
from test_support import sample_cve_all_data_1, sample_epss_data_1, sample_mentions_1, sample_cve_dict_1


class TestCveTupleBuilder(TestCase):

    def setUp(self) -> None:
        self.empy_cve_dict = {k: None for k in cve_tuple_fields}
        self.empty_cve = CveTuple(**self.empy_cve_dict)

        self.cve_tuple_dict = sample_cve_dict_1
        self.cve_tuple = CveTuple(**self.cve_tuple_dict)

        self.cve_all_data = sample_cve_all_data_1

        self.cve_builder = CveTupleBuilder()
        pass

    def test_reset(self):
        # prepare
        self.cve_builder._CveTupleBuilder__result_dict = self.cve_tuple_dict

        expected = self.cve_tuple_dict
        actual = self.cve_builder.get_result()

        self.assertNotEqual(expected, actual)

        # assert
        self.cve_builder.reset()

        expected = self.empty_cve
        actual = self.cve_builder.get_result()

        self.assertEqual(expected, actual)
        pass

    def test_build(self):
        # prepare
        self.cve_builder.build(self.cve_all_data, sample_epss_data_1, sample_mentions_1)

        # assert
        expected = self.cve_tuple
        actual = self.cve_builder.get_result()

        self.assertEqual(expected, actual)
        pass

    def test_get_result(self):
        # prepare
        self.cve_builder._CveTupleBuilder__result_dict = self.cve_tuple_dict

        # assert
        expected = self.cve_tuple
        actual = self.cve_builder.get_result()

        self.assertEqual(expected, actual)
        pass
