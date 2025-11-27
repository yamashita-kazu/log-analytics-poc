"""KQLクエリを構築するための関数群。"""


class SentinelKqlQuerys:
    """Sentinel用KQLクエリをまとめたクラス
    NOTE:
        - IPアドレスはtools.pyの関数内でformatして渡すこと。
    """

    @staticmethod
    def build_kql_query_common_security_log() -> str:
        """CommonSecurityLogテーブルを取得します。
        TODO:
            - どのEntityをターゲットに指定してsigninログを取得するか検討
            - カラムの絞り込み
        """
        kql_query = """
        CommonSecurityLog
        | where TimeGenerated >= ago(7d)
        | where SourceIP == "{ip_address}" or DestinationIP == "{ip_address}"
        | take 1
        """
        return kql_query

    @staticmethod
    def build_kql_query_signin_logs() -> str:
        """SigninLogsテーブルを取得します。"""
        kql_query = """
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
    """Microsoft Defender for Endpoint (MDE)用KQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_device_info() -> str:
        """MDEのDeviceInfoテーブルを取得します。"""
        kql_query = """
        DeviceInfo
        | where Timestamp >= ago(7d)
        | where IPAddresses contains "{ip_address}"
        """
        return kql_query

    @staticmethod
    def build_kql_query_device_events() -> str:
        """MDEのDeviceEventsテーブルを取得します。"""
        kql_query = """
        DeviceEvents
        | where Timestamp >= ago(7d)
        | where NetworkIP == "{ip_address}"
        """
        return kql_query

    @staticmethod
    def build_kql_query_device_file_events(ip_address: str) -> str:  # type: ignore
        """MDEのDeviceFileEventsテーブルを取得します。"""
        pass

    @staticmethod
    def build_kql_query_device_image_load_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_logon_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_network_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_network_info() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_process_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_registory_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_device_file_certificate_events() -> str:  # type: ignore
        pass


class Office365KqlQuerys:
    """Office365用KQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_email_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_email_url_info() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_email_attachment_info() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_post_delivery_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_url_click_events() -> str:  # type: ignore
        pass


class IdentityKqlQuerys:
    """ID・認証用イベントのKQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_identity_logon_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_identity_query_events() -> str:  # type: ignore
        pass

    @staticmethod
    def build_kql_query_directory_events() -> str:  # type: ignore
        pass


class CloudAppKqlQuerys:
    """Microsoft Defender for Cloud Apps (MCAS)用のKQLクエリをまとめたクラス"""

    @staticmethod
    def build_kql_query_cloud_app_events() -> str:  # type: ignore
        pass
