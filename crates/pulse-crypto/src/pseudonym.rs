use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive a stable anonymous pseudonym from an employee secret, tenant ID, and epoch ID.
///
/// `pseudonym = HMAC-SHA256(employee_secret, tenant_id_bytes || epoch_id_bytes)`
///
/// Properties:
/// - **Deterministic**: same inputs produce the same output
/// - **One-way**: cannot reverse to `employee_secret` without brute force
/// - **Tenant-scoped**: different `tenant_id` produces a different pseudonym
/// - **Epoch-scoped**: different `epoch_id` produces a different pseudonym
#[tracing::instrument(skip_all)]
pub fn derive_pseudonym(employee_secret: &[u8; 32], tenant_id: &[u8], epoch_id: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(employee_secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(tenant_id);
    mac.update(epoch_id);
    mac.finalize().into_bytes().into()
}

/// Generate a random 32-byte employee secret for pseudonym derivation.
///
/// This secret is stored only on the client device and never transmitted to any server.
pub fn generate_employee_secret() -> [u8; 32] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let secret = [1u8; 32];
        let tenant = b"tenant-a";
        let epoch = b"epoch-0";

        let p1 = derive_pseudonym(&secret, tenant, epoch);
        let p2 = derive_pseudonym(&secret, tenant, epoch);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_secrets_different_pseudonyms() {
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];
        let tenant = b"tenant-a";
        let epoch = b"epoch-0";

        assert_ne!(
            derive_pseudonym(&secret_a, tenant, epoch),
            derive_pseudonym(&secret_b, tenant, epoch),
        );
    }

    #[test]
    fn different_tenants_different_pseudonyms() {
        let secret = [1u8; 32];
        let epoch = b"epoch-0";

        assert_ne!(
            derive_pseudonym(&secret, b"tenant-a", epoch),
            derive_pseudonym(&secret, b"tenant-b", epoch),
        );
    }

    #[test]
    fn different_epochs_different_pseudonyms() {
        let secret = [1u8; 32];
        let tenant = b"tenant-a";

        assert_ne!(
            derive_pseudonym(&secret, tenant, b"epoch-0"),
            derive_pseudonym(&secret, tenant, b"epoch-1"),
        );
    }

    #[test]
    fn output_is_32_bytes() {
        let secret = [1u8; 32];
        let result = derive_pseudonym(&secret, b"t", b"e");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn generated_secrets_are_unique() {
        let s1 = generate_employee_secret();
        let s2 = generate_employee_secret();
        assert_ne!(s1, s2);
    }
}
