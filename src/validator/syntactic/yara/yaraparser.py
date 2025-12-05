import yara


def yara_syntax_checker(yara_rule: str) -> dict:
    """
    Checks the syntax of a given YARA rule string.
    Args:
        yara_rule (str): The YARA rule as a string.
    Returns:
        dict: A dictionary containing the status and error comment if any."""
    result = {
        "status": True,
        "error_comment": "No syntax errors detected.",
    }

    try:
        # Attempt to compile the YARA rule from the string
        yara.compile(source=yara_rule)
    except yara.SyntaxError as e:
        # Syntax error detected
        result["status"] = False
        result["error_comment"] = f"Syntax error: {str(e)}"
    except yara.Error as e:
        # Catch any other YARA-related error
        result["status"] = False
        result["error_comment"] = f"YARA error: {str(e)}"
    except Exception as e:
        # Catch any other general error
        result["status"] = False
        result["error_comment"] = f"General error: {str(e)}"

    return result
