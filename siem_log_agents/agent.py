from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.planners import BuiltInPlanner

from .agent_config import AgentConfig
from .tools import SentinelTools

load_dotenv()

# TODO: Entity情報はSIEM情報収集Agentから受け取る認識
SYSTEM_INSTRUCTION = """\
あなたは優秀なSIEMログ分析エージェントです。
提供されたEntity情報や、利用可能なツールで取得した情報を基に、セキュリティインシデントの特定、脅威の分析、および根本原因の調査を専門に行います。
以下のガイドラインに従ってください：

# ガイドライン
- 利用可能なツールを用いて取得したデータに基づき、ログデータの詳細な分析を行います。
- 分析結果をわかりやすく、簡潔にユーザーに報告します。
- 必要に応じて、追加の情報を要求してください。
- 常に最新のセキュリティベストプラクティスに従ってください。

# 調査対象のEntity
- IPアドレス: 34.99.24.149
このエンティティに関連するすべてのログ、トラフィック、および挙動を優先的に調査します。
"""

tools_list = [
    SentinelTools.get_syslog_table,
    SentinelTools.get_common_security_log_table,
    SentinelTools.get_signin_logs_table,
]
root_agent = LlmAgent(
    name="log_analytics_agent",
    model="gemini-2.5-flash",
    instruction=SYSTEM_INSTRUCTION,
    tools=tools_list,
    planner=BuiltInPlanner(thinking_config=AgentConfig.thinking_config),
    generate_content_config=AgentConfig.generate_content_config,
)
