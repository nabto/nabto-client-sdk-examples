## Thermostat client app

Features:

  * Discovery of local thermostats.
  * Pairing with a discovered thermostat.

## Configuration Files

The thermostat client can be configured using a JSON formatted
configuration file
`<HOME_DIR>/config/thermostat_client_config.json`. If the file does not
exist, the thermostat will create one with default values and
continue. The configuration file has the following format:

```
{
  "ServerKey": "sk-d8254c6f790001003d0c842d1b63b134",
  "ServerUrl": "https://pr-abcdefg.clients.nabto.net"
}
```

Once a client is paired with a device a file called
`state/thermostat_client_state.json` is created in the home dir. The
file contains all the information which is neccessary to communicate
with the thermostat.

The private key used by the client is stored as a PEM string in the
file `keys/client.key` in the home dir. If this file is missing, the
client will generate a key and store it automatically.

## Usage

The first time a client is run, it should be used to pair with the
thermostat device using the `--pair` option. Once paired, the remaining
thermostat features can be used with the paired device.
