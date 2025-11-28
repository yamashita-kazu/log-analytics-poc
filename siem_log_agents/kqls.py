"""KQLクエリを構築するための関数群。
TODO:
    - 不要なカラムはprojectで落とす
    - 時系列順にソートしてJSONで渡すことも可能
    - summarizeで要約することも可能
"""


class BuildEntityKQLs:
    """特定のエンティティ情報に基づいてKQLクエリを構築するクラス"""

    @staticmethod
    def build_ip_address_kql(ip_address: str, from_day: int = 7) -> str:
        """指定されたIPアドレスを起点に
        CommonSecurityLog、SigninLogs、Syslogテーブルを結合して取得するKQLクエリを構築します。

        Args:
            ip_address (str): 検索対象のIPアドレス
            from_day (int): 検索開始日数

        Returns:
            str: KQLクエリ
        """
        kql_query = f"""
        let target_ip = "{ip_address}";
        let from_day = ago({from_day}d);

        let CommonSecurityLogPart =
            CommonSecurityLog
            | where TimeGenerated >= from_day
            | where SourceIP == target_ip or DestinationIP == target_ip or RemoteIP == target_ip;

        let SigninLogsPart =
            SigninLogs
            | where TimeGenerated >= from_day
            | where IPAddress == target_ip;

        let SyslogPart =
            Syslog
            | where TimeGenerated >= from_day
            | where SyslogMessage has target_ip or Computer has target_ip;

        CommonSecurityLogPart
        | union SigninLogsPart, SyslogPart
        | sort by TimeGenerated desc
        """
        return kql_query


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
