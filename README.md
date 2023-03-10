# ev0te

## Configuration

The `src/` folder contains a **JSON** file `config.json`, which by default, has the following contents:

```json
{
    "v_server": {
        "host": "127.0.0.1",
        "port": 6969,
        "keyfiles": {
            "public": "./s_pubkey.pem",
            "private": "./s_privkey.pem"
        }
    },
    "v_client": {
        "keyfiles": {
            "public": "./c_pubkey.pem",
            "private": "./c_privkey.pem"
        }
    },
    "i_server": {
        "host": "127.0.0.1",
        "port": 6970,
        "keyfiles": {
            "public": "./i_pubkey.pem",
            "private": "./i_privkey.pem"
        }
    }
}
```

The various options specify the configurations for the respective elements in the project:
- `v_server` defines the configuration for the main server 
- `v_client` defines the configuration for the main client
- `i_server` defines the configuration for the identity server 

