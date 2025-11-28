"""
Agentの設定を管理するモジュール
"""

from google.genai.types import (
    FunctionCallingConfig,
    FunctionCallingConfigMode,
    GenerateContentConfig,
    HarmBlockThreshold,
    HarmCategory,
    SafetySetting,
    ThinkingConfig,
    ToolConfig,
)


class AgentConfig:
    """Agentの設定クラス"""

    model_config = {
        "extra": "allow",
    }

    _model_safety_settings: list[SafetySetting] = [
        SafetySetting(
            category=HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
        SafetySetting(
            category=HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
        SafetySetting(
            category=HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
    ]
    _function_calling_config = ToolConfig(
        function_calling_config=FunctionCallingConfig(
            mode=FunctionCallingConfigMode.AUTO,
        )
    )
    thinking_config = ThinkingConfig(thinking_budget=0)
    generate_content_config = GenerateContentConfig(
        safety_settings=_model_safety_settings,
        tool_config=_function_calling_config,
        temperature=1.0,
    )
