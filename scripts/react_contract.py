"""Strict evaluation of recorded ReAct responses. Never repair before scoring."""
import json


def strict_loads(text):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON property")
            result[name] = value
        return result

    def reject_constant(value):
        raise ValueError("Non-JSON numeric constant")

    return json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)


def evaluate(content, tools):
    try:
        step = strict_loads(content)
        if not isinstance(step, dict):
            return False, False, False, None
        valid_json = set(step) == {"thought", "action", "action_input"} and isinstance(step.get("thought"), str)
        action = step.get("action")
        valid_action = isinstance(action, str) and (action == "final_answer" or action in tools)
        value = step.get("action_input")
        if action == "final_answer":
            valid_input = isinstance(value, str) and bool(value.strip())
        else:
            valid_input = isinstance(value, dict) or isinstance(value, str) and isinstance(strict_loads(value), dict)
        return valid_json, valid_action, valid_input, action
    except (ValueError, TypeError):
        return False, False, False, None
