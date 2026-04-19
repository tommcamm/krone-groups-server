use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::common::{DeviceId, IdentityPk};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationRequest {
    pub device_id: DeviceId,
    pub identity_pk: IdentityPk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationResponse {
    pub device_id: DeviceId,
    #[serde(with = "time::serde::rfc3339")]
    pub registered_at: OffsetDateTime,
}
