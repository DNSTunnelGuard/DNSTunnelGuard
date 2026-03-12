

**/update_runtime_config POST**
Update specific confgiuration values of the runtime config.
Expects a 'true' or 'false' in save query, controlling whether it
replaces the runtime config file.

Expects json to update config options, i.e.
[analyzer]
sus_percentage_threshold = 1

```json
{
    "analyzer": {
        "sus_percentage_threshold": 1
    }
}
```

--- 

**/reload_runtimg_config POST**

Update the runtime config with a new runtime config file.
Expects a 'true' or 'false' in 'save' parameter, controlling whether it
replaces the runtime config file.

Expects a file named 'file' with the config file data

**/reset_runtime_config GET**

Reset the runtime config to the saved runtime config 

**/terminate GET**

Terminate the tunnel guard program 



