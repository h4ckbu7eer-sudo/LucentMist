import unittest
from react_contract import evaluate


class StrictReActContractTests(unittest.TestCase):
    def test_real_duplicate_action_input_is_not_counted_as_success(self):
        value = '{"thought":"done","action":"final_answer","action_input":"first","action_input":"second"}'
        self.assertFalse(evaluate(value, set())[0])

    def test_extra_field_fails_the_production_three_field_contract(self):
        value = '{"thought":"done","action":"final_answer","action_input":"answer","extra":1}'
        self.assertFalse(evaluate(value, set())[0])

    def test_tool_and_final_legal_examples(self):
        for value in ('{"thought":"check","action":"ssl_check","action_input":{"target":"127.0.0.1"}}',
                      '{"thought":"done","action":"final_answer","action_input":"answer"}'):
            self.assertEqual((True, True, True), evaluate(value, {"ssl_check"})[:3])

    def test_unknown_action_and_empty_final_fail(self):
        self.assertFalse(evaluate('{"thought":"","action":"unknown","action_input":{}}', set())[1])
        self.assertFalse(evaluate('{"thought":"","action":"final_answer","action_input":" "}', set())[2])

    def test_duplicate_nested_argument_is_ambiguous(self):
        self.assertFalse(evaluate('{"thought":"","action":"ssl_check","action_input":{"port":80,"port":443}}', {"ssl_check"})[0])

    def test_non_json_numeric_constant_is_rejected(self):
        self.assertFalse(evaluate('{"thought":"","action":"ssl_check","action_input":{"port":NaN}}', {"ssl_check"})[0])
