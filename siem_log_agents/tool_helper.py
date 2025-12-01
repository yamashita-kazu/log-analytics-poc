import logging
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


class ToolHelpers:
    """ツールのヘルパー群。低レベルな処理を担当"""

    def _util_access_token(
        self, tenant_id: str, client_id: str, client_secret: str, resource_uri: str
    ) -> str:
        """共通のアクセストークン取得ロジック"""
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
        token_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "resource": resource_uri,
        }
        token_response = requests.post(token_url, data=token_payload)
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token: str = token_data.get("access_token")
        if not access_token:
            raise ValueError(
                f"Failed to retrieve access token for resource: {resource_uri}."
            )
        return access_token

    def get_access_token(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> str:
        """Sentinel用のアクセストークンを取得"""
        RESOURCE_URI = "https://management.azure.com"
        return self._util_access_token(
            tenant_id, client_id, client_secret, RESOURCE_URI
        )

    def get_access_token_mde(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> str:
        """MDE用のアクセストークンを取得"""
        RESOURCE_URI = "https://api.securitycenter.microsoft.com"
        return self._util_access_token(
            tenant_id, client_id, client_secret, RESOURCE_URI
        )

    def execute_kql_query(
        self,
        access_token: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
        kql_query: str,
    ) -> Any:
        """Log Analyticsワークスペースに対してKQLクエリを実行"""
        query_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/query?api-version=2017-10-01"
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-type": "application/json",
        }
        query_payload = {"query": kql_query}
        query_response = requests.post(query_url, headers=headers, json=query_payload)
        query_response.raise_for_status()
        logger.debug("\nKQLクエリが正常に実行されました。\n")
        return query_response.json()

    def get_log_analytics_table_schema(
        self,
        access_token: str,
        table_name: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> dict[str, Any]:
        """指定されたLog Analyticsテーブルのスキーマ情報を取得します。"""
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"/tables/{table_name}?api-version=2025-07-01"
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        table = response.json()
        schema = table["properties"]["schema"]
        return {
            "table": schema["name"],
            "columns": schema.get("columns", []) + schema.get("standardColumns", []),
        }
