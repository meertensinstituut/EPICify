# EPICify
A Java library and tool to interact with an EPIC v2 or Handle v8 PID service.

```sh
$ mvn clean package
$ java -jar cli/target/epicify.jar
java -jar epicify.jar <options>

new handle   : <path to config> new <suffix>? <uri>
get handle   : <path to config> get <prefix/suffix>
update handle: <path to config> upd <prefix/suffix> <uri>
delete handle: <path to config> del <prefix/suffix>
               NOTE: there might be a nodelete policy active!
```

## Handle v8 PID service

```
Configuration file for a Handle v8 PID service looks like
```xml
<PIDService>
  <host>https://[server:port]/api/handles/</host>
  <HandlePrefix>11.T12345</HandlePrefix>
  <private_key>user_private_key.pem</private_key>
  <server_certificate_only>server_certificate_if_selfsigned.crt</server_certificate_only>
  <private_certificate>user_certificate.pem</private_certificate>
  <status>test</status>
</PIDService>
```

_NOTES_:
1) ```private_key```, ```private_certificate``` are required
2) in case of selfsigned server certificate, use this command to get the server certificate and save it as a ```.crt``` file 
```sh 
openssl s_client -connect [server:port] -showcerts 
```
3) change ```test``` into ```production```

--

## EPIC v2 PID service

Where a config looks like this:

```xml
<PIDService>
  <URI>http://www.pidconsortium.eu/</URI>
  <HandlePrefix>12345</HandlePrefix>
  <hostName>www.pidconsortium.eu</hostName>
  <userName>epic</userName>
  <password>test</password>
  <email>me@example.com</email>
  <status>test</status>
</PIDService>
```

_NOTES_:
1) change ```test``` into ```production```

--

_NOTE_: EPICify is based on work by Jan Pieter Kunst and others @ http://www.meertens.knaw.nl/ontwikkeling

--

[epicify](http://www.urbandictionary.com/define.php?term=Epicify) (3)
