import asyncio
import json
import logging
import os
from typing import Any, Final

from dotenv import load_dotenv

from .kqls import BuildEntityKQLs, MDEKqlQuerys, SentinelKqlQuerys
from .tool_helper import tool_helpers

load_dotenv()

# TODO: テナントIDなどは統一させる？
# --- Sentinel ---
SENTINEL_CLIENT_ID: Final[str] = os.getenv("SENTINEL_CLIENT_ID", "")
SENTINEL_CLIENT_SECRET: Final[str] = os.getenv("SENTINEL_CLIENT_SECRET", "")
SENTINEL_TENANT_ID: Final[str] = os.getenv("SENTINEL_TENANT_ID", "")
SUBSCRIPTION_ID: Final[str] = os.getenv("SUBSCRIPTION_ID", "")
RESOURCE_GROUP_NAME: Final[str] = os.getenv("RESOURCE_GROUP_NAME", "")
WORKSPACE_NAME: Final[str] = os.getenv("WORKSPACE_NAME", "")

# --- Microsoft Defender XDR  ---
MDE_CLIENT_ID: Final[str] = os.getenv("MDE_CLIENT_ID", "")
MDE_CLIENT_SECRET: Final[str] = os.getenv("MDE_CLIENT_SECRET", "")
MDE_TENANT_ID: Final[str] = os.getenv("MDE_TENANT_ID", "")

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)


class AnalyzeEntityTools:
    """KQLクエリビルド用のツールをまとめたクラス"""

    @staticmethod
    def analyze_ip_entity(ip_address: str, from_day: int = 7) -> Any:
        """指定されたIPアドレスを起点に
        CommonSecurityLog、SigninLogs、Syslogテーブルを結合して取得するKQLクエリを実行します。
        Args:
            ip_address (str): 調査対象のIPアドレス
            from_day (int): 検索開始日数（デフォルトは7日間）

        Returns:
            Any: KQLクエリを実行した結果
        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if not access_token:
            return
        kql_query = BuildEntityKQLs.build_ip_address_kql(
            ip_address=ip_address, from_day=from_day
        )
        logger.info(f"\n実行するKQLクエリ:\n{kql_query}\n")
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

        return table_rows


class SentinelTools:
    """Sentinel関連のツールをまとめたクラス
    TODO:
        - 毎回アクセストークンを取得しているが、キャッシュする仕組みを入れた方が良いかも
        - 型アノテーションの見直し
    """

    @staticmethod
    async def get_common_security_log_table(ip_address: str) -> Any:
        """CommonSecurityLogテーブルを取得します。
        主にサードパーティのネットワーク製品（ファイアウォールなど）から取り込まれたログデータを格納するために使用されるテーブルであり、
        ネットワーク通信に関する多くのエンティティ情報を含んでいます。

        Args:
            ip_address (str): 検索対象のIPアドレス
        Returns:
            Any: セキュリティログテーブルの行データ

        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if not access_token:
            return

        kql_query = SentinelKqlQuerys.build_kql_query_common_security_log()
        print(
            f"\n=== 実行するKQLクエリ ===:\n{kql_query.format(ip_address=ip_address)}"
        )
        table_rows = _execute_kql_and_get_rows(
            access_token, kql_query.format(ip_address=ip_address)
        )

        return table_rows

    @staticmethod
    async def get_signin_logs_table(ip_address: str) -> Any:
        """SigninLogsテーブルを取得します。

        Args:
            ip_address (str): 検索対象のIPアドレス

        Returns:
            Any: サインインログテーブルの行データ

        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if not access_token:
            return

        kql_query = SentinelKqlQuerys.build_kql_query_signin_logs()
        print(
            f"\n=== 実行するKQLクエリ ===:\n{kql_query.format(ip_address=ip_address)}"
        )
        table_rows = _execute_kql_and_get_rows(
            access_token, kql_query.format(ip_address=ip_address)
        )

        return table_rows

    @staticmethod
    async def get_syslog_table() -> Any:
        """Syslogテーブルを取得します。

        Returns:
            Any: Syslogテーブルの行データ
        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if not access_token:
            return

        kql_query = SentinelKqlQuerys.build_kql_query_syslog_logs()
        print(f"\n=== 実行するKQLクエリ ===:\n{kql_query}")
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

        return table_rows


class MDETools:
    """Microsoft Defender for Endpoint (MDE)関連のツールをまとめたクラス"""

    @staticmethod
    async def get_mde_device_info_table(ip_address: str) -> Any:
        """MDEのDeviceInfoテーブルを取得します。

        Args:
            ip_address (str): 検索対象のIPアドレス

        Returns:
            Any: MDEのDeviceInfoテーブルの行データ

        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token_mde,
            MDE_TENANT_ID,
            MDE_CLIENT_ID,
            MDE_CLIENT_SECRET,
        )
        if not access_token:
            return

        kql_query = MDEKqlQuerys.build_kql_query_device_info(ip_address)
        print(f"実行するKQLクエリ:\n{kql_query}")
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

        return table_rows


def _execute_kql_and_get_rows(
    access_token: str,
    kql_query: str,
) -> Any:
    """KQLクエリを実行した結果を扱いやすい形にするutil関数"""

    logger.debug(f"\nGenerated KQL Query:\n{kql_query}\n")

    query_data = tool_helpers.util_api_call(
        tool_helpers.execute_kql_query,
        access_token,
        SUBSCRIPTION_ID,
        RESOURCE_GROUP_NAME,
        WORKSPACE_NAME,
        kql_query,
    )

    if not query_data:
        return

    tables = query_data.get("tables", [])
    if tables:
        logger.debug(json.dumps(tables, indent=2, ensure_ascii=False))
        # TODO: rowだけではなく、スキーマ情報も返すようにする方が良いかも
        # return tables[0].get("rows")
        return tables[0]
    else:
        logger.debug("Query returned no tables.")
        return


if __name__ == "__main__":
    # table_rows = asyncio.run(
    #     SentinelTools.get_signin_logs_table(ip_address="34.99.24.149")
    # )
    # logger.info("\n--- signin log ---")
    # logger.info(json.dumps(table_rows, indent=2, ensure_ascii=False))

    # common_log_rows = asyncio.run(
    #     SentinelTools.get_common_security_log_table(ip_address="34.99.24.149")
    # )
    # logger.info("\n--- common security log ---")
    # logger.info(json.dumps(common_log_rows, indent=2, ensure_ascii=False))

    table_rows = asyncio.run(
        AnalyzeEntityTools.analyze_ip_entity(ip_address="34.99.24.149")
    )
    logger.info(json.dumps(table_rows, indent=2, ensure_ascii=False))
