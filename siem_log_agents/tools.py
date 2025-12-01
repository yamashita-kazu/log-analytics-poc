import logging
from typing import Any

from dotenv import load_dotenv

from .kql_executor import MdeKqlExecutor, SentinelKqlExecutor
from .kqls import BuildEntityKQLs, MDEKqlQuerys, SentinelKqlQuerys
from .tool_helper import ToolHelpers

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

tool_helpers = ToolHelpers()

sentinel_executor = SentinelKqlExecutor(tool_helpers)
mde_executor = MdeKqlExecutor(tool_helpers)


class AnalyzeEntityTools:
    """エンティティ情報を起点に固定のKQLクエリを実行するツールをまとめたクラス"""

    def __init__(self, sentinel_executor: SentinelKqlExecutor):
        self._sentinel_executor = sentinel_executor

    def analyze_ip_entity(self, ip_address: str, from_day: int = 7) -> Any:
        """指定されたIPアドレスを起点に
        CommonSecurityLog、SigninLogs、Syslogテーブルを結合して取得するKQLクエリを実行します。
        Args:
            ip_address (str): 調査対象のIPアドレス
            from_day (int): 検索開始日数（デフォルトは7日間）

        Returns:
            Any: KQLクエリを実行した結果
        """
        kql_query = BuildEntityKQLs.build_ip_address_kql(
            ip_address=ip_address, from_day=from_day
        )
        logger.info(f"\n実行するKQLクエリ:\n{kql_query}\n")

        table_rows = self._sentinel_executor.execute_kql_query(kql_query)

        return table_rows

    def analyze_user_entity(self, user_name: str, from_day: int = 7) -> Any:
        pass


class BuildKQLTools:
    """任意のKQLクエリを実行するためのツールをまとめたクラス"""

    def __init__(self, sentinel_executor: SentinelKqlExecutor):
        self._sentinel_executor = sentinel_executor

    async def execute_kql_query(self, kql_query: str) -> dict[str, str]:
        """指定されたKusto Query Language (KQL) クエリを実行し、結果を返します。
        このツールは、エージェントが動的にKQLクエリを実行するために使用されます。

        Args:
            kql_query (str): 実行するKQLクエリ

        Returns:
            KQLクエリの実行結果を示す辞書
            成功した場合（例）: {"status": "success", "kql_query_result": ...}
            失敗した場合（例）: {"status": "error", "error_message": ...}
        """
        logger.info(f"\n実行するKQLクエリ:\n{kql_query}\n")

        # KQLの実行はExecutorに任せる
        result: dict[str, str] = self._sentinel_executor.execute_kql_query(kql_query)

        return result

    async def get_log_analytics_table_schema(self, table_name: str) -> dict[str, Any]:
        """指定されたLog Analyticsテーブルのスキーマ情報を取得します。
        このツールは、エージェントがテーブルのスキーマ情報を取得するために使用されます。

        Args:
            table_name (str): 取得するテーブル名
            例: "Syslog", "SigninLogs", "CommonSecurityLog"

        Returns:
            dict: テーブルのスキーマ情報
            成功した場合（例）: {"status": "success", "table_schema": ...}
            失敗した場合（例）: {"status": "error", "error_message": ...}
        """
        schema_result: dict[str, Any] = (
            self._sentinel_executor.get_log_analytics_table_schema(table_name)
        )

        return schema_result


class SentinelTools:
    """Sentinel関連のツールをまとめたクラス"""

    def __init__(self, sentinel_executor: SentinelKqlExecutor):
        self._sentinel_executor = sentinel_executor

    async def get_common_security_log_table(self, ip_address: str) -> Any:
        """CommonSecurityLogテーブルを取得します。
        主にサードパーティのネットワーク製品（ファイアウォールなど）から取り込まれたログデータを格納するために使用されるテーブルであり、
        ネットワーク通信に関する多くのエンティティ情報を含んでいます。

        Args:
            ip_address (str): 検索対象のIPアドレス
        Returns:
            Any: セキュリティログテーブルの行データ

        """
        kql_query = SentinelKqlQuerys.build_kql_query_common_security_log()
        print(
            f"\n=== 実行するKQLクエリ ===:\n{kql_query.format(ip_address=ip_address)}"
        )
        table_rows = self._sentinel_executor.execute_kql_query(
            kql_query.format(ip_address=ip_address)
        )

        return table_rows

    async def get_signin_logs_table(self, ip_address: str) -> Any:
        """SigninLogsテーブルを取得します。

        Args:
            ip_address (str): 検索対象のIPアドレス

        Returns:
            Any: サインインログテーブルの行データ

        """
        kql_query = SentinelKqlQuerys.build_kql_query_signin_logs()
        print(
            f"\n=== 実行するKQLクエリ ===:\n{kql_query.format(ip_address=ip_address)}"
        )
        table_rows = self._sentinel_executor.execute_kql_query(
            kql_query.format(ip_address=ip_address)
        )

        return table_rows

    async def get_syslog_table(self) -> Any:
        """Syslogテーブルを取得します。

        Returns:
            Any: Syslogテーブルの行データ
        """
        kql_query = SentinelKqlQuerys.build_kql_query_syslog_logs()
        print(f"\n=== 実行するKQLクエリ ===:\n{kql_query}")
        table_rows = self._sentinel_executor.execute_kql_query(kql_query)

        return table_rows


class MDETools:
    """Microsoft Defender for Endpoint (MDE)関連のツールをまとめたクラス"""

    def __init__(self, mde_executor: MdeKqlExecutor):
        self._mde_executor = mde_executor

    async def get_mde_device_info_table(self, ip_address: str) -> Any:
        """MDEのDeviceInfoテーブルを取得します。

        Args:
            ip_address (str): 検索対象のIPアドレス

        Returns:
            Any: MDEのDeviceInfoテーブルの行データ

        """
        kql_query = MDEKqlQuerys.build_kql_query_device_info(ip_address)
        print(f"実行するKQLクエリ:\n{kql_query}")
        table_rows = self._mde_executor.execute_kql_query(kql_query)

        return table_rows


if __name__ == "__main__":
    import asyncio
    import json

    kql_builder = BuildKQLTools(
        sentinel_executor=SentinelKqlExecutor(tool_helpers=tool_helpers)
    )
    table_rows = asyncio.run(kql_builder.execute_kql_query(kql_query="Syslog | take 1"))
    print(json.dumps(table_rows, indent=2, ensure_ascii=False))
    schema_info = asyncio.run(
        kql_builder.get_log_analytics_table_schema(table_name="Syslog")
    )
    print(json.dumps(schema_info, indent=2, ensure_ascii=False))
