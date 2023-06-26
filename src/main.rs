#[macro_use]
extern crate rocket;
use abe_webapp::{actions::*, app_config::AppConfig};
use rocket::serde::Serialize;
use rocket::Config;
use rocket_dyn_templates::{context, Template};
use std::env;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Serialize)]
struct MenuItem {
    name: String,
    link: String,
}

#[derive(Serialize)]
struct Menu {
    entries: Vec<MenuItem>,
}

#[get("/")]
fn index() -> Template {
    let menu = Menu {
        entries: vec![
            MenuItem {
                name: "Show encrypted storage".to_string(),
                link: "/encrypted-storage".to_string(),
            },
            MenuItem {
                name: "Decrypt storage".to_string(),
                link: "/get-user-key".to_string(),
            },
            MenuItem {
                name: "Update storage".to_string(),
                link: "/get-plaintext-policy".to_string(),
            },
        ],
    };

    Template::render("index", context! {menu: &menu})
}

#[launch]
fn rocket() -> _ {
    let current_dir = env::current_dir().unwrap().to_string_lossy().to_string();
    let config = AppConfig {
        gk_path: current_dir.to_owned() + "/src/keys/global_keys/global_parameters.json",
        auth_dir: current_dir.to_owned() + "/src/keys/authority_keys",
        user_dir: current_dir.to_owned() + "/src/keys/user_keys",
        storage_path: current_dir.to_owned() + "/src/storage/storage.json",
    };

    let addr_config = Config {
        address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        port: 8000,
        ..Config::default()
    };

    rocket::custom(addr_config)
        .manage(config)
        .attach(Template::fairing())
        .mount(
            "/",
            routes![
                index,
                update_storage,
                decrypt_storage,
                show_encrypted_storage,
                get_userkey,
                get_plaintext_policy
            ],
        )
}
