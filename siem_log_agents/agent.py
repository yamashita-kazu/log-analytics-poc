from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.planners import BuiltInPlanner

from .agent_config import AgentConfig
from .kql_executor import SentinelKqlExecutor
from .prompts import SYSTEM_INSTRUCTION
from .tool_helper import ToolHelpers
from .tools import BuildKQLTools

load_dotenv()

tool_helpers = ToolHelpers()

# KQL Executorインスタンス化
sentinel_executor = SentinelKqlExecutor(tool_helpers=tool_helpers)

# ツールクラスのインスタンス化
kql_builder = BuildKQLTools(sentinel_executor=sentinel_executor)

tools_list = [
    kql_builder.execute_kql_query,
    kql_builder.get_log_analytics_table_schema,
]

root_agent = LlmAgent(
    name="log_analytics_agent",
    model="gemini-2.5-flash",
    instruction=SYSTEM_INSTRUCTION,
    tools=tools_list,
    planner=BuiltInPlanner(thinking_config=AgentConfig.thinking_config),
    generate_content_config=AgentConfig.generate_content_config,
)
