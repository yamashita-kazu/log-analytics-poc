import asyncio
import json
import logging
import os
from typing import Any

from dotenv import load_dotenv

from .kqls import MDEKqlQuerys, SentinelKqlQuerys
from .tool_helper import tool_helpers

load_dotenv()

# --- Sentinel ---
SENTINEL_CLIENT_ID = os.getenv("SENTINEL_CLIENT_ID")
SENTINEL_CLIENT_SECRET = os.getenv("SENTINEL_CLIENT_SECRET")
SENTINEL_TENANT_ID = os.getenv("SENTINEL_TENANT_ID")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME")
WORKSPACE_NAME = os.getenv("WORKSPACE_NAME")

# --- MDE ---
MDE_CLIENT_ID = os.getenv("MDE_CLIENT_ID")
MDE_CLIENT_SECRET = os.getenv("MDE_CLIENT_SECRET")
MDE_TENANT_ID = os.getenv("MDE_TENANT_ID")

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)


class SentinelTools:
    """Sentinel関連のツールをまとめたクラス"""

    @staticmethod
    async def get_security_incident_table() -> Any:
        """最新のインシデントに関するSecurity Incidentのログテーブルを取得します。
        Returns:
            Any: セキュリティログテーブルの行データ
        """

        # 1. アクセストークンを取得
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if not access_token:
            return None

        # 2. インシデントを取得
        incidents = tool_helpers.util_api_call(
            tool_helpers.get_incidents,
            access_token,
            SUBSCRIPTION_ID,
            RESOURCE_GROUP_NAME,
            WORKSPACE_NAME,
        )
        if not incidents:
            return None

        # 3. 最新のインシデント情報を取得し、ログ出力
        first_incident = incidents[0]
        incident_id = first_incident.get("name")
        logger.debug(f"インシデントIDを使用中: {incident_id}")
        logger.info(
            f"最新のインシデント概要:\n {json.dumps(first_incident, indent=2, ensure_ascii=False)[:1000]}"
        )
        # 4. インシデントのアラートを取得
        alerts = tool_helpers.util_api_call(
            tool_helpers.get_alerts_for_incident,
            access_token,
            SUBSCRIPTION_ID,
            RESOURCE_GROUP_NAME,
            WORKSPACE_NAME,
            incident_id,
        )
        if alerts:
            logger.info(f"取得したアラート件数: {len(alerts)}")
            logger.debug(
                f"取得したアラート:\n {json.dumps(alerts, indent=2, ensure_ascii=False)}"
            )
            # first_alert = alerts[0]
            # alert_id = first_alert["properties"]["systemAlertId"]
            # logger.debug(f"アラートIDを使用中: {alert_id}")

        # 5. KQLクエリを構築して実行
        kql_query = SentinelKqlQuerys.build_kql_query_security_incident()
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

        return table_rows

    @staticmethod
    async def get_common_security_log_table() -> Any:
        """CommonSecurityLogテーブルを取得します。
        主にサードパーティのネットワーク製品（ファイアウォールなど）から取り込まれたログデータを格納するために使用されるテーブルであり、
        ネットワーク通信に関する多くのエンティティ情報を含んでいます。

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
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

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
        print(f"Executing KQL Query:\n{kql_query.format(ip_address=ip_address)}")
        table_rows = _execute_kql_and_get_rows(
            access_token, kql_query.format(ip_address=ip_address)
        )

        return table_rows


class MDETools:
    """MDE関連のツールをまとめたクラス"""

    @staticmethod
    async def get_mde_alerts_table() -> Any:
        """MDEのAlertテーブルを取得します。

        Returns:
            Any: MDEのアラートテーブルの行データ

        """
        access_token = tool_helpers.util_api_call(
            tool_helpers.get_access_token_mde,
            MDE_TENANT_ID,
            MDE_CLIENT_ID,
            MDE_CLIENT_SECRET,
        )
        if not access_token:
            return

        kql_query = MDEKqlQuerys.build_kql_query_mde_alerts()
        table_rows = _execute_kql_and_get_rows(access_token, kql_query)

        return table_rows


def _execute_kql_and_get_rows(
    access_token: str,
    kql_query: str,
) -> Any:
    """KQLクエリを実行し、結果のテーブル行を返します。"""

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
    table_rows = asyncio.run(
        SentinelTools.get_signin_logs_table(ip_address="34.99.24.149")
    )
    logger.info("\n--- レスポンス ---")
    logger.info(json.dumps(table_rows, indent=2, ensure_ascii=False))

    # common_log_rows = asyncio.run(SentinelTools.get_common_security_log_table())
    # logger.info("\n--- レスポンス ---")
    # logger.info(json.dumps(common_log_rows, indent=2, ensure_ascii=False))
