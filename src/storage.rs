use rabe::schemes::aw11::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone)]
pub struct Storage<T> {
    data: Vec<T>,
}

impl<T> Serialize for Storage<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.data.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Storage<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = Vec::deserialize(deserializer)?;
        Ok(Storage { data })
    }
}

impl<T> Storage<T>
where
    T: Clone,
{
    pub fn default() -> Storage<T> {
        Storage {
            data: Vec::<T>::default(),
        }
    }

    pub fn new(data: Vec<T>) -> Storage<T> {
        Storage { data: data }
    }

    pub fn get_data(&self) -> Vec<T> {
        self.data.clone()
    }
}

impl Storage<Option<Vec<u8>>> {
    fn to_string(&self) -> String {
        let mut res = String::new();
        if self.data.is_empty() {
            res.push_str("Storage is empty");
        } else {
            res.push_str("Decrypted storage:");
            for (n, e) in self.data.iter().enumerate() {
                let mut entry = String::from("\nEntry #");
                entry.push_str(&n.to_string());
                entry.push_str("\t Plaintext: ");
                match e {
                    Some(plaintext) => {
                        let plaintext = String::from_utf8_lossy(plaintext);
                        entry.push_str(&plaintext)
                    }
                    None => entry.push_str("NaN"),
                };
                res.push_str(&entry);
            }
        }
        res
    }
}

impl Storage<Aw11Ciphertext> {
    pub fn update(&mut self, new_ct: Aw11Ciphertext) {
        self.data.push(new_ct)
    }

    fn to_string(&self) -> String {
        let mut res = String::new();
        if self.data.is_empty() {
            res.push_str("Storage is empty");
        } else {
            res.push_str("Encrypted storage:");
            for (n, e) in self.data.iter().enumerate() {
                let policy = &e._policy.0;

                let mut entry = String::from("\nEntry #");
                entry.push_str(&n.to_string());
                entry.push_str("\t Encryption policy: ");
                entry.push_str(&policy);

                res.push_str(&entry);
            }
        }
        res
    }

    pub fn decrypt(&self, gk: &Aw11GlobalKey, sk: &Aw11SecretKey) -> Storage<Option<Vec<u8>>> {
        let mut decrypted_data = Vec::new();
        for ct in self.data.iter() {
            match decrypt(gk, sk, ct) {
                Ok(plaintext) => decrypted_data.push(Some(plaintext)),
                Err(_) => decrypted_data.push(None),
            }
        }
        Storage::new(decrypted_data)
    }
}
