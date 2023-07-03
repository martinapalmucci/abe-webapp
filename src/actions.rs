use crate::app_config::AppConfig;
use crate::storage::Storage;
use crate::{get_filenames, Serializable};
use rabe::schemes::aw11::{encrypt, Aw11Ciphertext, Aw11GlobalKey, Aw11PublicKey, Aw11SecretKey};
use rabe::utils::policy::pest::PolicyLanguage;
use rocket::data::ToByteUnit;
use rocket::futures::io;
use rocket::http::Status;
use rocket::response::status;
use rocket::Data;
use rocket::{get, post, State};
use rocket_dyn_templates::{context, Template};

#[get("/new-action")]
pub fn new_action() -> Template {
    Template::render("new_action", context! {})
}

#[post("/upload", format = "multipart", data = "<data>")]
pub async fn decrypt_storage_2(
    data: Data<'_>,
    config: &State<AppConfig>,
) -> Result<Template, status::Custom<String>> {
    let user_key = from_data_to_userkey(data)
        .await
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    let gk = Aw11GlobalKey::load_from_file(&config.gk_path).unwrap(); // Global key
    let storage = Storage::load_from_file(&config.storage_path).unwrap(); // Storage

    // Decrypt storage
    let dec_storage = storage.decrypt(&gk, &user_key);
    let temp = Template::render(
        "decrypt_storage",
        context! {user_id: user_key._gid, storage_data: dec_storage.get_data(), storage_empty: dec_storage.get_data().is_empty()},
    );
    Ok(temp)
}

async fn from_data_to_userkey(file: Data<'_>) -> Result<Aw11SecretKey, Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    file.open(256.kibibytes()).stream_to(&mut data).await?;

    let data = String::from_utf8(data)?;
    let lines: Vec<&str> = data.lines().collect();

    let subline = lines
        .get(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid line"))?;
    println!("subline = {:#?}", subline);

    let userkey = serde_json::from_str(subline)?;
    Ok(userkey)
}

/// Action: show encrypted storage
#[get("/encrypted-storage")]
pub fn show_encrypted_storage(config: &State<AppConfig>) -> Template {
    let storage: Storage<Aw11Ciphertext> = Storage::load_from_file(&config.storage_path).unwrap();
    Template::render(
        "encrypted_storage",
        context! {storage_data: &storage.get_data(), storage_empty: storage.get_data().is_empty()},
    )
}

/// Action: decrypt storage
#[derive(rocket::FromForm)]
pub struct FormUserKey {
    pub userkey_filename: String,
}

#[get("/get-user-key")]
pub fn get_userkey() -> Template {
    Template::render("get_userkey", context! {})
}

#[post("/decrypt-storage", data = "<form_data>")]
pub fn decrypt_storage(
    form_data: rocket::form::Form<FormUserKey>,
    config: &State<AppConfig>,
) -> Template {
    // Load variables
    let user_path = config.user_dir.to_owned() + "/" + &form_data.userkey_filename;
    let user_key = Aw11SecretKey::load_from_file(&user_path).unwrap(); // User key
    let gk = Aw11GlobalKey::load_from_file(&config.gk_path).unwrap(); // Global key
    let storage = Storage::load_from_file(&config.storage_path).unwrap(); // Storage

    // Decrypt storage
    let dec_storage = storage.decrypt(&gk, &user_key);
    Template::render(
        "decrypt_storage",
        context! {user_id: user_key._gid, storage_data: dec_storage.get_data(), storage_empty: dec_storage.get_data().is_empty()},
    )
}

// Action: update storage
#[derive(rocket::FromForm)]
pub struct FormPlaintextPolicy {
    pub plaintext: String,
    pub policy: String,
}

#[get("/get-plaintext-policy")]
pub fn get_plaintext_policy() -> Template {
    Template::render("update_storage", context! {is_added: false})
}

#[post("/update-storage", data = "<form_data>")]
pub fn update_storage(
    form_data: rocket::form::Form<FormPlaintextPolicy>,
    config: &State<AppConfig>,
) -> Template {
    let ciphertext = encrypt(
        &Aw11GlobalKey::load_from_file(&config.gk_path).unwrap(),
        &get_pks(config),
        &form_data.policy,
        PolicyLanguage::HumanPolicy,
        &form_data.plaintext.as_bytes(),
    )
    .unwrap(); // Ciphertext

    let mut storage = Storage::load_from_file(&config.storage_path).unwrap();
    storage.update(ciphertext);
    let _ = storage.save_to_file(&config.storage_path);

    Template::render("update_storage", context! {is_added: true})
}

fn get_pks(config: &State<AppConfig>) -> Vec<Aw11PublicKey> {
    let mut pks: Vec<Aw11PublicKey> = Vec::new();
    let boh = get_filenames(&config.auth_dir);
    match boh {
        Ok(filenames) => {
            for filename in filenames {
                pks.push(Aw11PublicKey::load_from_file(&filename).unwrap());
            }
        }
        Err(error) => {
            eprintln!("Error: {}", error);
        }
    };
    pks
}
