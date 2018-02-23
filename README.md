# EPICify
A Java library and tool to interact with an EPIC v2 PID service.

## Version 2.0
Unified old version call and new version call. From both command line and direct call to PIDService, the version number can be omitted. 

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
Configuration file for ver. 2.0 looks like
```xml
<PIDService>
  <version>8</version>
  <baseuri>https://[server:port]/api/handles/</baseuri>
  <private_key>user_private_key.pem</private_key>
  <server_certificate_only>server_certificate_if_selfsigned.crt</server_certificate_only>
  <private_certificate>user_certificate.pem</private_certificate>
  <HandlePrefix>11.T12345</HandlePrefix>
  <status>staging</status>
</PIDService>
```

--
_NOTE_:
1) private_key, private_certificate are required
2) In case of selfsigned server certificate, use this command to get the server certificate and save it as a .crt file 
```sh 
openssl s_client -connect {HOSTNAME}:{PORT} -showcerts 
```
--


## Version 1.0
```sh
$ mvn clean package
$ java -jar cli/target/epicify.jar 
java -jar epicify.jar <options>

new handle   : <path to config> new <suffix>? <uri>
get handle   : <path to config> get <prefix/suffix>
update handle: <path to config> upd <prefix/suffix> <uri>
delete handle: <path to config> del <prefix/suffix>
               NOTE: there might be a nodelete policy active!

batch        : <path to config> csv <FILE.csv>
               NOTE: CSV columns: <suffix>,<uri>
               NOTE: will do an upsert, i.e., insert for a new suffix
                     and an update for an existing suffix
```

Where a config looks like this:

```xml
<PIDService>
  <hostName>www.pidconsortium.eu</hostName>
  <URI>http://www.pidconsortium.eu/</URI>
  <HandlePrefix>12345</HandlePrefix>
  <userName>epic</userName>
  <password>test</password>
  <email>me@example.com</email>
  <status>test</status>
</PIDService>
```

Change ```test``` into ```production```.

--

_NOTE_: EPICify is based on work by Jan Pieter Kunst and others @ http://www.meertens.knaw.nl/ontwikkeling

--

[epicify](http://www.urbandictionary.com/define.php?term=Epicify) (3)
