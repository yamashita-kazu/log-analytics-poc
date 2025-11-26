import logging
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(message)s",
)
logger = logging.getLogger(__name__)


class ToolHelpers:
    """ツール関連のヘルパー関数をまとめたクラス。"""

    def get_access_token(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> Any:
        """Azure ADからアクセストークンを取得"""
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
        token_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "resource": "https://management.azure.com",
        }
        token_response = requests.post(token_url, data=token_payload)
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Failed to retrieve access token.")
        return access_token

    def get_access_token_mde(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> Any:
        """MDE用のアクセストークンを取得"""
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
        token_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "resource": "https://api.securitycenter.microsoft.com",
        }
        token_response = requests.post(token_url, data=token_payload)
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Failed to retrieve MDE access token.")
        return access_token

    def get_incidents(
        self,
        access_token: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> Any:
        """セキュリティインシデントのリストを取得"""
        incidentlist_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"/providers/Microsoft.SecurityInsights/incidents?api-version=2024-01-01-preview"
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-type": "application/json",
        }
        logger.debug("インシデントを取得中...")
        incidentlist_response = requests.get(incidentlist_url, headers=headers)
        incidentlist_response.raise_for_status()
        incidents = incidentlist_response.json().get("value", [])
        if not incidents:
            raise ValueError("No incidents found.")
        logger.debug(f"{len(incidents)} 件のインシデントが見つかりました。")
        return incidents

    def get_alerts_for_incident(
        self,
        access_token: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
        incident_id: str,
    ) -> Any:
        """特定のインシデントのアラートを取得"""
        alerts_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}/alerts?api-version=2024-01-01-preview"
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-type": "application/json",
        }
        logger.debug(f"インシデント {incident_id} のアラートを取得中...")
        alerts_response = requests.post(alerts_url, headers=headers)
        alerts_response.raise_for_status()
        alerts = alerts_response.json().get("value", [])
        if not alerts:
            raise ValueError(
                f"インシデント {incident_id} にアラートが見つかりませんでした。"
            )
        logger.debug(f"Found {len(alerts)} alerts.")
        return alerts

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

    def util_api_call(self, f: Any, *args: Any, **kwargs: Any) -> Any:
        """APIコールをラップしてエラー処理をおこなう"""
        try:
            return f(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.error(f"\nAPI Request Failed: {e}")
            if e.response is not None:
                logger.error(f"Response Status: {e.response.status_code}")
                logger.error(f"Response Body: {e.response.text}")
            return None
        except (ValueError, IndexError) as e:
            logger.error(f"\nData Processing Error: {e}")
            return None
        except Exception as e:
            logger.error(f"\nAn unexpected error occurred: {e}")
            return None


tool_helpers = ToolHelpers()
