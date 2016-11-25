# EPICify
A Java library and tool to interact with an EPIC v2 PID service.

```sh
$ mvn clean package
$ java -jar target/epicify.jar 
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
  <hostName>www.pidconsortium.eu/</hostName>
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
