from unittest import TestCase

from cve_api import CveTuple, CveTupleBuilder, cve_tuple_fields
from test_support import cve_all_data_1, epss_data, mentions


class TestCveTupleBuilder(TestCase):

    def setUp(self) -> None:
        self.empy_cve_dict = {k: None for k in cve_tuple_fields}
        self.empty_cve = CveTuple(**self.empy_cve_dict)

        self.cve_tuple_dict = {'id': 'CVE-2019-1010218',
                               'cvss2': None,
                               'cvss31': 'HIGH',
                               'score': 5.0,
                               'vector': 'NETWORK',
                               'complexity': 'LOW',
                               'epss': None,
                               'date': '2019-07-22T18:15:10.917',
                               'product': 'cherokee_web_server',
                               'versions': '1.2.103',
                               'poc': 'https://i.imgur.com/PWCCyir.png',
                               'description': "Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet.",
                               'mentions': None,
                               'elimination': 'ne ebu'}
        self.cve_tuple = CveTuple(**self.cve_tuple_dict)

        self.cve_all_data = cve_all_data_1

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
        self.cve_builder.build(self.cve_all_data, epss_data, mentions)

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
