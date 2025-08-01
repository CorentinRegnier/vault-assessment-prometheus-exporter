"""
Class for monitoring secret (KV2) expiration information in HashiCorp Vault.
"""

import requests
import logging

from typing import Optional

from vault_monitor.expiration_monitor.expiration_monitor import ExpirationMonitor
from vault_monitor.expiration_monitor.vault_time import ExpirationMetadata

TIMEOUT = 60
LOGGER = logging.getLogger(__name__)


class SecretExpirationMonitor(ExpirationMonitor):
    """
    Class for monitoring KV2 secrets
    """

    last_renewal_gauge_name = "vault_secret_last_renewal_timestamp"
    last_renewal_gauge_description = "Timestamp for when a secret was last updated."
    expiration_gauge_name = "vault_secret_expiration_timestamp"
    expiration_gauge_description = "Timestamp for when a secret should expire."

    def __init__(
        self,
        mount_point,
        monitored_path,
        vault_client,
        service_name,
        prometheus_labels,
        metadata_fieldnames,
        monitor_flag=None,
    ):
        super().__init__(
            mount_point,
            monitored_path,
            vault_client,
            service_name,
            prometheus_labels,
            metadata_fieldnames,
        )
        self.monitor_flag = monitor_flag

    def get_expiration_info(self) -> Optional[ExpirationMetadata]:
        response = requests.get(
            f"{self.vault_client.url}/v1/{self.mount_point}/metadata/{self.monitored_path}",
            headers={
                "X-Vault-Namespace": self.vault_client.adapter.namespace,
                "X-Vault-Token": self.vault_client.token,
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()

        data = response.json().get("data", {})
        metadata = data.get("custom_metadata") or {}

        if self.monitor_flag:
            field = self.monitor_flag.get("field", "monitor")
            truthy = self.monitor_flag.get("truthy_value", "true")
            if metadata.get(field) != truthy:
                LOGGER.info(
                    "Secret '%s' skipped (monitor_flag '%s' != '%s')",
                    self.monitored_path,
                    field,
                    truthy,
                )
                return None

        return ExpirationMetadata.from_metadata(
            metadata,
            self.last_renewed_timestamp_fieldname,
            self.expiration_timestamp_fieldname,
        )
