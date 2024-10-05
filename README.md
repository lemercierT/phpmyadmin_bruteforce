# phpMyAdmin Bruteforce

## Rust installation 

1. On windows and linux:

```
https://www.rust-lang.org/tools/install
```

2. Once Rust is installed

```
git clone https://github.com/lemercierT/phpmyadmin_bruteforce.git
cd phpmyadmin_bruteforce/pma_bruteforcer/target/debug/
```

3. Example usage
```
[Usage]
.\pma_login_bruteforcer.exe --url http://xxxx/phpmyadmin
                            --pma_username xxxx
                            --wordlist Your/wordlist/path
                            --threads 0-125 (recommended)
``` 

4. For the test I used it against my local database.

For the test I changed my local database password to "IamASecureKey123@!" at the 4959 place of the passlist.txt wordlist.

In less than 30s we obtained :
```
$ ./pma_login_bruteforcer.exe --url http://127.0.0.1/phpmyadmin --pma_username root --wordlist ../../passlist.txt --threads 100
[+] Found creds root:IamASecureKey123@!
```

## Disclaimer
The phpmyadmin_bruteforce tool is intended solely for educational purposes and authorized security testing. The use of this software to attempt unauthorized access to any systems, networks, or data without the explicit consent of the system owner is illegal and may result in severe civil and/or criminal penalties.

The author of this tool, including contributors and any affiliated parties, assumes no responsibility for any misuse or damages caused by the use of this tool. By using this tool, you agree to only use it in compliance with all applicable local, national, and international laws.

Always ensure that you have explicit permission from the owner before testing any system's security.

Use responsibly.


