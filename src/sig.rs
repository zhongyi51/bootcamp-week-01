//check whether the jwt signature is valid
pub trait SignatureChecker {
    //checks whether the jwt signature is valid
    fn check(&self, prefix: &[u8], given: &[u8]) -> anyhow::Result<()>;

    //sign the given data
    fn sign(&self, prefix: &[u8]) -> anyhow::Result<Vec<u8>>;
}

mod sig_impl {
    use anyhow::{bail, Ok};
    use hmac_sha256::HMAC;

    use super::SignatureChecker;

    //HS256
    pub struct HS256SignatureChecker {
        secret: Vec<u8>,
    }

    impl HS256SignatureChecker {
        pub fn from_secret(secret: &[u8]) -> anyhow::Result<HS256SignatureChecker> {
            Ok(HS256SignatureChecker {
                secret: secret.to_vec(),
            })
        }
    }

    impl SignatureChecker for HS256SignatureChecker {
        fn check(&self, prefix: &[u8], given: &[u8]) -> anyhow::Result<()> {
            let expected = self.sign(prefix)?;
            if expected != given {
                bail!("invalid signature");
            }
            Ok(())
        }

        fn sign(&self, prefix: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut h = HMAC::new(&self.secret);
            h.update(prefix);
            let signed = h.finalize();
            Ok(signed.to_vec())
        }
    }
}

pub mod instance {
    use std::{
        collections::HashMap,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::{anyhow, bail, Ok};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    use super::{sig_impl::HS256SignatureChecker, SignatureChecker};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct JwtHeader {
        pub alg: String,
        pub typ: String,
    }

    //build all signature instances
    pub struct SigInstanceCollection {
        instance_map: HashMap<&'static str, Box<dyn SignatureChecker>>,
    }

    impl SigInstanceCollection {
        pub fn create_from_path(path: &str) -> anyhow::Result<SigInstanceCollection> {
            let content = fs::read(path)?;
            let conf: serde_json::Value = serde_json::from_slice(&content)?;

            let mut hm = HashMap::new();

            //HS256
            let secret = conf
                .get("HS256")
                .ok_or(anyhow!("no hs256 conf"))?
                .get("secret")
                .ok_or(anyhow!("no hs256 secret"))?
                .as_str()
                .ok_or(anyhow!("hs256 secret is not str"))?;
            hm.insert(
                "HS256",
                Box::new(HS256SignatureChecker::from_secret(secret.as_bytes())?)
                    as Box<dyn SignatureChecker>,
            );

            Ok(SigInstanceCollection { instance_map: hm })
        }

        //jwt: base64(header).base64(payload).base64(Sig(base64(header).base64(payload)+secret))
        pub fn check(&self, seq_base64: &str) -> anyhow::Result<(JwtHeader, serde_json::Value)> {
            //get each parts
            let mut split = seq_base64.split('.');
            let header_base64 = split.next().ok_or(anyhow!("no jwt header"))?;
            let payload_base64 = split.next().ok_or(anyhow!("no payload"))?;
            let signature = split.next().ok_or(anyhow!("no signature"))?;

            //check hs256
            let header: JwtHeader =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_base64)?)?;
            let expected = URL_SAFE_NO_PAD.decode(signature)?;

            let checker = self
                .instance_map
                .get(header.alg.as_str())
                .ok_or(anyhow!("unsupported alg: {}", &header.alg))?;
            checker.check(
                format!("{}.{}", header_base64, payload_base64).as_bytes(),
                &expected,
            )?;

            let payload: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_base64)?)?;
            if let Some(exp) = payload.get("exp") {
                let exp_ts = exp
                    .as_u64()
                    .ok_or(anyhow!("invalid ext, should be positive integer"))?;
                if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > exp_ts {
                    bail!("token is expired");
                }
            }
            Ok((header, payload))
        }

        //jwt: base64(header).base64(payload).base64(Sig(base64(header).base64(payload)+secret))
        pub fn signature(
            &self,
            header: &JwtHeader,
            payload: &serde_json::Value,
        ) -> anyhow::Result<String> {
            let header_base64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
            let payload_base64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);

            let signer = self
                .instance_map
                .get(header.alg.as_str())
                .ok_or(anyhow!("unsupported alg: {}", &header.alg))?;
            let r = signer.sign(format!("{}.{}", header_base64, payload_base64).as_bytes())?;

            let sig_base64 = URL_SAFE_NO_PAD.encode(r);

            Ok(format!(
                "{}.{}.{}",
                header_base64, payload_base64, sig_base64
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Ok;
    use serde_json::json;

    use super::instance::{JwtHeader, SigInstanceCollection};

    #[test]
    fn test_jwt() -> anyhow::Result<()> {
        let v = SigInstanceCollection::create_from_path("./secret_conf.json")?;
        let (_h,p)=v.check("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.keH6T3x1z7mmhKL1T3r9sQdAxxdzB6siemGMr_6ZOwU")?;
        assert_eq!(p["name"], "John Doe");
        Ok(())
    }

    #[test]
    fn test_jwt2() -> anyhow::Result<()> {
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        };
        let payload = json!(
            {
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022
            }
        );
        let v = SigInstanceCollection::create_from_path("./secret_conf.json")?;
        let res = v.signature(&header, &payload)?;
        assert_eq!(res,"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.keH6T3x1z7mmhKL1T3r9sQdAxxdzB6siemGMr_6ZOwU");
        Ok(())
    }

    #[test]
    fn test_jwt3() -> anyhow::Result<()> {
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        };
        let payload = json!(
            {
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022
            }
        );
        let v = SigInstanceCollection::create_from_path("./secret_conf.json")?;
        let res = v.signature(&header, &payload)?;
        v.check(&res)?;
        Ok(())
    }
}
