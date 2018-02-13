# WP Flak (Fliegerabwehrkanone) - Wordpress Security Scanner/Exploiter

## ✠ Wordpress ✠
- Version Finder
- Themes / Plugins Infomations
- Users Extraction (Various Methods)
- Auto Users Weak Passwords Checker
- Exploit Finder
- Exploiter

- ✠ 𝔡𝔢𝔲𝔱𝔰𝔠𝔥𝔩𝔞𝔫𝔡 ✠

     <p align="center"><img src="https://upload.wikimedia.org/wikipedia/commons/e/e7/Bundesarchiv_Bild_101I-635-4000-24%2C_Deutschland%2C_Flakturm_mit_Vierlingsflak.jpg" /></p>
     
     
# ✠ Donations / Support ✠
If you want to support/help me/my projects :

- **BTC** : 1N9BgzVVT8ye3UEUXb2p7Pum7RbmEx3byz
- **ETC** : 0x789bc32e951ccdaa5702d70fe02e21f596baa085
- **ETH** : 0x789bc32e951ccdaa5702d70fe02e21f596baa085
- **LTC** : LVSPDkX5Dr95cKqQnCMoLgYyzGBdtSsi3y
- **TRX** : 0x789bc32e951ccdaa5702d70fe02e21f596baa085
- **ZEC** : t1cctQEJxBvDhcXHdP4hKpS3LimRN2sFsbN


# ✠ Installation ✠

- wpFlak requires perl 5.18 to work and perlbrew (which provides it) may fail during installation
- keep in mind that's only a beta version

   ```bash
      sudo sh install/perlbrew_install.sh
      sudo sh install/install.sh
   ```

# ✠ Usage ✠

- See help menu :

   ```bash
      perl wpflak.pl --help
   ```

- TOR proxified requests example

   ```bash
      perl wpflak.pl --url http://www.example.com/ --proxy socks://127.0.0.1:9050 --users
   ```
