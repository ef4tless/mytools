#!/usr/bin/env python3

import unittest

from kctf_switch_rewriter import (
    eval_simple_condition,
    parse_simple_condition,
    rewrite_to_switch,
)


class SwitchRewriterTests(unittest.TestCase):
    def test_simple_conditions(self):
        self.assertEqual(parse_simple_condition("cmd == 0x114"), ("cmd", "==", 0x114))
        self.assertEqual(parse_simple_condition("2064 <= cmd"), ("cmd", ">=", 2064))
        self.assertTrue(eval_simple_condition("cmd > 10", "cmd", 11))
        self.assertFalse(eval_simple_condition("cmd != 3", "cmd", 3))
        self.assertIsNone(eval_simple_condition("idx < 3", "cmd", 1))

    def test_if_ladder_becomes_switch_without_statement_loss(self):
        source = """int f(int cmd)
{
  int result = 0;
  if ( cmd > 1 )
  {
    if ( cmd == 2 )
    {
      result = 20;
    }
    else
    {
      if ( cmd != 3 )
        goto BAD;
      result = 30;
    }
  }
  else
  {
    if ( cmd != 1 )
      goto BAD;
    result = 10;
  }
  goto out;
BAD:
  result = -1;
out:
  return result;
}
"""
        commands = [
            {"command": 1, "action": "ONE"},
            {"command": 2, "action": "TWO"},
            {"command": 3, "action": "THREE"},
        ]
        result = rewrite_to_switch(source, commands)
        self.assertTrue(result["success"])
        self.assertEqual(result["variable"], "cmd")
        self.assertEqual(result["detail_validation"]["coverage"], 1.0)
        self.assertFalse(result["detail_validation"]["missing_lines"])
        rewritten = result["rewritten"]
        self.assertIn("switch ( cmd )", rewritten)
        self.assertIn("case 0x1: // ONE", rewritten)
        self.assertIn("case 0x2: // TWO", rewritten)
        self.assertIn("case 0x3: // THREE", rewritten)
        self.assertIn("result = 10;", rewritten)
        self.assertIn("result = 20;", rewritten)
        self.assertIn("result = 30;", rewritten)
        self.assertIn("goto BAD;", rewritten)

    def test_sequential_dispatch_region_becomes_switch(self):
        source = """int g(int cmd)
{
  int result = -1;
  if ( cmd <= 2 )
  {
    if ( cmd == 1 )
    {
      result = 11;
      goto out;
    }
    if ( cmd == 2 )
    {
      result = 22;
      goto out;
    }
    goto BAD;
  }
  if ( cmd == 3 )
  {
    result = 33;
    goto out;
  }
  if ( cmd != 4 )
    goto BAD;
  result = 44;
  goto out;
BAD:
  result = -22;
out:
  return result;
}
"""
        commands = [
            {"command": 1, "action": "ONE"},
            {"command": 2, "action": "TWO"},
            {"command": 3, "action": "THREE"},
            {"command": 4, "action": "FOUR"},
        ]
        result = rewrite_to_switch(source, commands)
        self.assertTrue(result["success"])
        self.assertEqual(result["detail_validation"]["coverage"], 1.0)
        self.assertEqual(result["detail_validation"]["occurrence_coverage"], 1.0)
        rewritten = result["rewritten"]
        for value, detail in ((1, "11"), (2, "22"), (3, "33"), (4, "44")):
            self.assertIn("case 0x%x:" % value, rewritten)
            self.assertIn("result = %s;" % detail, rewritten)


if __name__ == "__main__":
    unittest.main()
