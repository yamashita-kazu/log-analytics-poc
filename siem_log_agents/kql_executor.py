import json
import logging
import os
from typing import Any, Final

import requests
from dotenv import load_dotenv

from .tool_helper import ToolHelpers

logger = logging.getLogger(__name__)

load_dotenv()

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


class BaseKqlExecutor:
    """KQLクエリ実行のための基底クラス
    SentinelやMDEなど、各サービスで継承することを想定
    """

    def __init__(self, tool_helpers: ToolHelpers):
        """ToolHelpersインスタンスを受け取るコンストラクタ"""
        self._tool_helpers = tool_helpers

    def _util_api_call(self, f: Any, *args: Any, **kwargs: Any) -> Any:
        """APIコールをラップしてエラー処理をおこなう"""
        try:
            return f(*args, **kwargs)

        except requests.exceptions.RequestException as e:
            logger.error(f"\nAPI Request Failed: {e}")
            if e.response is not None:
                logger.error(f"Response Status: {e.response.status_code}")
                logger.error(f"Response Body: {e.response.text}")

                # KQLクエリ実行時のエラーの場合、エラーメッセージを返す（LLMに読ませる）
                if f == self._tool_helpers.execute_kql_query:
                    return {"status": "error", "error_message": e.response.text}
            return None

        except (ValueError, IndexError) as e:
            logger.error(f"\nData Processing Error: {e}")
            return {"status": "error", "error_message": str(e)}

        except Exception as e:
            logger.error(f"\nAn unexpected error occurred: {e}")
            return {"status": "error", "error_message": str(e)}

    def _execute_kql_and_get_rows(
        self,
        access_token: str,
        kql_query: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> dict[str, Any]:
        """KQLクエリを実行し、結果を整形する"""

        logger.debug(f"\nGenerated KQL Query:\n{kql_query}\n")

        query_data = self._util_api_call(
            self._tool_helpers.execute_kql_query,
            access_token,
            subscription_id,
            resource_group_name,
            workspace_name,
            kql_query,
        )

        if isinstance(query_data, dict) and "error_message" in query_data:
            return query_data  # エラーをそのまま返す

        tables = query_data.get("tables", [])
        if tables:
            logger.debug(json.dumps(tables, indent=2, ensure_ascii=False))
            # TODO: rowだけではなく、スキーマ情報も返すようにする方が良いかも
            # return tables[0].get("rows")
            return {"status": "success", "kql_query_result": tables[0]}
        else:
            logger.debug("Query returned no tables.")
            return {
                "status": "success",
                "kql_query_result": "Query returned no tables.",
            }


class SentinelKqlExecutor(BaseKqlExecutor):

    def _get_sentinel_access_token(self) -> Any:
        """Sentinel 向けのアクセストークンを取得"""
        access_token = self._util_api_call(
            self._tool_helpers.get_access_token,
            SENTINEL_TENANT_ID,
            SENTINEL_CLIENT_ID,
            SENTINEL_CLIENT_SECRET,
        )
        if isinstance(access_token, str):
            return access_token
        return None

    def execute_kql_query(self, kql_query: str) -> dict[str, Any]:
        """指定されたKusto Query Language (KQL) クエリを実行し、結果を返します。"""
        access_token = self._get_sentinel_access_token()
        if not access_token:
            return {
                "status": "error",
                "error_message": "Failed to obtain access token",
            }

        return self._execute_kql_and_get_rows(
            access_token,
            kql_query,
            SUBSCRIPTION_ID,
            RESOURCE_GROUP_NAME,
            WORKSPACE_NAME,
        )

    def get_log_analytics_table_schema(self, table_name: str) -> dict[str, Any]:
        """指定されたLog Analyticsテーブルのスキーマ情報を取得します。"""
        access_token = self._get_sentinel_access_token()
        if not access_token:
            return {
                "status": "error",
                "error_message": "Failed to obtain access token",
            }

        schema = self._util_api_call(
            self._tool_helpers.get_log_analytics_table_schema,
            access_token,
            table_name,
            SUBSCRIPTION_ID,
            RESOURCE_GROUP_NAME,
            WORKSPACE_NAME,
        )

        if isinstance(schema, dict) and "error_message" in schema:
            return schema
        if schema is None:
            return {
                "status": "error",
                "error_message": "Failed to get table schema due to API error.",
            }

        return {"status": "success", "table_schema": schema}


class MdeKqlExecutor(BaseKqlExecutor):
    """MDE向けのKQLクエリ実行クラス"""

    def _get_mde_access_token(self) -> Any:
        """MDE用のアクセストークンを取得"""
        access_token = self._util_api_call(
            self._tool_helpers.get_access_token_mde,
            MDE_TENANT_ID,
            MDE_CLIENT_ID,
            MDE_CLIENT_SECRET,
        )
        if isinstance(access_token, str):
            return access_token
        return None

    def execute_kql(self, kql_query: str) -> dict[str, Any]:  # type: ignore
        """MDEのKQLクエリを実行する"""
        pass
