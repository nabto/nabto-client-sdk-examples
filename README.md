# Nabto Client SDK examples

Example applications for Nabto Edge Client SDK.

## Simple CoAP
The simple CoAP example illustrates how to connect to a device and invoke a CoAP
endpoint. This example is intented to use with the
[simple_coap](https://docs.nabto.com/developer/guides/get-started/embedded/examples.html)
device example. Before running the device, it should be [configured in the
basestation](https://docs.nabto.com/developer/guides/get-started/embedded/applications.html).
From this configuration, the client requires the Product ID and Device ID of the
device to connect to. The device example uses a predefined demo SCT, so running
this example does not require a server key or SCT to be provided. The client can
then be run using:

```
./simple_coap/simple_coap_client -d <Device ID (de-...)> -p <Product ID (pr-...)>
```

## Simple Stream
The simple stream example illustrates how to connect to a device and open a
stream to send data to and from the device. This example is intented to use with
the
[simple_stream](https://github.com/nabto/nabto-embedded-sdk/tree/master/examples/simple_stream)
device example. Before running the device, it should be [configured in the
basestation](https://docs.nabto.com/developer/guides/get-started/embedded/applications.html).
From this configuration, the client requires the Product ID and Device ID of the
device to connect to. The device example uses a predefined demo SCT, so running
this example does not require a server key or SCT to be provided. The client can
then be run using:

```
./simple_stream/simple_stream_client -d <Device ID (de-...)> -p <Product ID (pr-...)>
```

When the client is connected, stream data can be typed into the application and
send to the device which will echo the data back to the client.

## Simple Tunnel
The simple tunnel example illustrates how to connect to a device and open a TCP
tunnel to make an SSH connection to the device. This example is intented to use
with the
[simple_tunnel](https://github.com/nabto/nabto-embedded-sdk/tree/master/examples/simple_tunnel)
device example. Before running the device, it should be [configured in the
basestation](https://docs.nabto.com/developer/guides/get-started/embedded/applications.html).
From this configuration, the client requires the Product ID and Device ID of the
device to connect to. The device example uses a predefined demo SCT, so running
this example does not require a server key or SCT to be provided. The client can
then be run using:

```
./simple_tunnel/simple_tunnel_client -d <Device ID (de-...)> -p <Product ID (pr-...)> --service ssh
```

When the client is connected, it will print the endpoint exposed
locally to allow SSH access to the device:

```
connecting to pr-12345678.de-abcdefgh
Opened a connection to the device and opened a tunnel to the service: ssh
The service is exposed at TCP 127.0.0.1:41879
Press enter to continue...
```

From another terminal, make an SSH session to the device through the
tunnel using the port number shown by the client:

```
ssh 127.0.0.1 -p 41879
```

In this example, the SSH client will then connect to the Nabto Edge
client on port `41879`. The Nabto Edge client creates a stream to the
device. The device then connects a TCP socket to port `22` on the
device.


## Thermostat
The Thermostat client example illustrates using
the
[Nabto IAM](https://docs.nabto.com/developer/guides/iam/intro.html)
module for authentication and authorization using
the
[Thermostat](https://github.com/nabto/nabto-embedded-sdk/tree/master/examples/thermostat) example
device. Before running the device, it should be
[configured in the basestation](https://docs.nabto.com/developer/guides/get-started/embedded/applications.html). From
this configuration, the client requires the Product ID and Device ID
of the device to connect to.
The IAM module restricts access to the device until the client
has completed a pairing process. The IAM module in the thermostat
device is configured to only allow clients to pair from the local
network. Once the device is up and running, the client can be paired
interactively while on the same LAN as the device using:

```
./thermostat/thermostat_client --pair
```

Once paired, other the client can access the remaining device features
like getting the state of the thermostat:

```
./thermostat/thermostat_client --get
```


## Building

```
mkdir _build
cd _build
cmake -DCMAKE_INSTALL_PREFIX=install ..
cmake --build . --config Release --target install
```

The built binaries is located in the folder named `_build/install`

## Nabto Edge Client Libraries

All the example client applications depend on the Nabto Edge Client SDK. This
consists of some headers and some libraries. These files are copied to the
`nabto_client_sdk_library` folder from the Nabto Edge Client SDK releases repository:
https://github.com/nabto/nabto-client-sdk-releases

The library can easily be updated to a new version by running the below command
or manually copying the desired version of the artifacts to this repository.

E.g. to update client libraries to v5.12.0 one can use the following command.
```
cd nabto_client_sdk_library
curl -sSL https://github.com/nabto/nabto-client-sdk-releases/archive/refs/tags/v5.12.0.tar.gz | tar -xzf - --strip-components=1
```
