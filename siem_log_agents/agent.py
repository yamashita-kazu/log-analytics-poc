from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.planners import BuiltInPlanner

from .agent_config import AgentConfig
from .prompts import SYSTEM_INSTRUCTION_1, SYSTEM_INSTRUCTION_2  # noqa: F401
from .tools import AnalyzeEntityTools, SentinelTools  # noqa: F401

load_dotenv()

tools_list = [
    # SentinelTools.get_syslog_table,
    # SentinelTools.get_common_security_log_table,
    # SentinelTools.get_signin_logs_table,
    AnalyzeEntityTools.analyze_ip_entity,
]
root_agent = LlmAgent(
    name="log_analytics_agent",
    model="gemini-2.5-flash",
    instruction=SYSTEM_INSTRUCTION_2,
    tools=tools_list,
    planner=BuiltInPlanner(thinking_config=AgentConfig.thinking_config),
    generate_content_config=AgentConfig.generate_content_config,
)
