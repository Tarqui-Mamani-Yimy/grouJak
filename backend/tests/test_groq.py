from backend.app.attacker import _openai_tools
from backend.app.groq_client import extract_content


def test_groq_extract_content() -> None:
    assert extract_content({"choices": [{"message": {"content": "hola"}}]}) == "hola"
    assert extract_content({"choices": []}) == ""
    assert extract_content({}) == ""


def test_tools_use_openai_function_schema() -> None:
    tools = _openai_tools()
    assert len(tools) == 4
    assert all(tool["type"] == "function" for tool in tools)
    names = {tool["function"]["name"] for tool in tools}
    assert names == {
        "revisar_rutas",
        "revisar_headers",
        "probar_login",
        "reportar_hallazgo",
    }
    login = next(tool for tool in tools if tool["function"]["name"] == "probar_login")
    parameters = login["function"]["parameters"]
    assert parameters["type"] == "object"
    assert "usuario" in parameters["properties"]
    assert "clave" in parameters["properties"]
