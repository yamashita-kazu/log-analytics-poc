"""KQLクエリを構築するためのユーティリティ関数群。"""


class SentinelKqlQuerys:
    """Sentinel用KQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_common_security_log(ip_address: str) -> str:
        """CommonSecurityLogテーブルを取得します。
        TODO:whereでEntityを指定する
        """
        kql_query = f"""
        CommonSecurityLog
        | where TimeGenerated >= ago(7d)
        | where IPAddresses contains "{ip_address}"
        | take 10
        """
        return kql_query

    @staticmethod
    def build_kql_query_signin_logs(ip_address: str) -> str:
        """SigninLogsテーブルを取得します。
        TODO: どのEntityをターゲットに指定してsigninログを取得するか検討
        """
        kql_query = f"""
        SigninLogs
        | where TimeGenerated >= ago(7d)
        | where IPAddress contains "{ip_address}"
        | sort by TimeGenerated desc
        """
        return kql_query

    @staticmethod
    def build_kql_query_syslog_logs() -> str:
        """Syslogテーブルを取得します."""
        kql_query = """
        Syslog
        | take 1
        """
        return kql_query


class MDEKqlQuerys:
    """MDE用KQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_mde_alerts() -> str:
        """MDEのAlertテーブルを取得します。"""
        kql_query = """
        DeviceInfo
        | where Timestamp >= ago(7d)
        |
        """
        return kql_query
