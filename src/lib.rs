pub mod actions;
pub mod app_config;
pub mod storage;

use std::{
    fs,
    io::{self, Write},
};

pub trait Serializable {
    fn save_to_file(&self, file_path: &str) -> Result<(), io::Error>;
    fn load_from_file(file_path: &str) -> Result<Self, io::Error>
    where
        Self: Sized;
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Serializable for T {
    fn save_to_file(&self, file_path: &str) -> Result<(), io::Error> {
        let serialized = serde_json::to_string(self)?;
        let mut file = fs::File::create(file_path)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    fn load_from_file(file_path: &str) -> Result<Self, io::Error> {
        let file_contents = fs::read_to_string(file_path)?;
        let deserialized = serde_json::from_str(&file_contents)?;
        Ok(deserialized)
    }
}

pub fn get_filenames(folder_path: &str) -> Result<Vec<String>, io::Error> {
    let entries = fs::read_dir(folder_path)?;
    let mut result = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let path = path.to_str().unwrap();
            result.push(String::from(path));
        }
    }

    Ok(result)
}
