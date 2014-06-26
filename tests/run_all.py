import unittest
import test_server

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(test_server.test_suite())
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
