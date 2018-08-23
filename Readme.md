# Freddy the Serial(isation) Killer  - Deserialization Bug Finder #
A Burp Suite extension to aid in detecting and exploiting serialisation libraries/APIs.

This useful extension was originally developed by Nick Bloor (@nickstadb) for NCC Group and is mainly based on the work of Alvaro Muñoz and Oleksandr Mirosh, [Friday the 13th: JSON Attacks](https://www.blackhat.com/us-17/briefings.html#friday-the-13th-json-attacks), which they presented at Black Hat USA 2017 and DEF CON 25. In their work they reviewed a range of JSON and XML serialisation libraries for Java and .NET and found that many of them support serialisation of arbitrary runtime objects and as a result are vulnerable in the same way as many serialisation technologies are - snippets of code (POP gadgets) that execute during or soon after deserialisation can be controlled using the properties of the serialized objects, often opening up the potential for arbitrary code or command execution.

Further modules supporting more formats including YAML and AMF are also included, based on the paper [Java Unmarshaller Security - Turning your data into code execution](https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf) and tool [marshalsec](https://github.com/mbechler/marshalsec) by Moritz Bechler.

This Burp Suite extension implements both passive and active scanning to identify and exploit vulnerable libraries.

## Freddy Features ##

### Passive Scanning ###
Freddy can passively detect the use of potentially dangerous serialisation libraries and APIs by watching for type specifiers or other signatures in HTTP requests and by monitoring HTTP responses for exceptions issued by the target libraries. For example the library `FastJson` uses a JSON field `$types` to specify the type of the serialized object.

### Active Scanning ###
Freddy includes active scanning functionality which attempts to both detect and, where possible, exploit affected libraries.

Active scanning attempts to detect the use of vulnerable libraries using three methods: exception-based, time-based, and Collaborator-based.

#### Exception Based ####
In exception-based active scanning, Freddy inserts data into the HTTP request that should trigger a known target-specific exception or error message. If this error message is observed in the application's response then an issue is raised.

#### Time Based ####
In some cases time-based payloads can be used for detection because operating system command execution is triggered during deserialisation and this action blocks execution until the OS command has finished executing. Freddy uses payloads containing `ping [-n|-c] 21 127.0.0.1` in order to induce a time delay in these cases.

#### Collaborator Based ####
Collaborator-based payloads work either by issuing a `nslookup` command to resolve the Burp Suite Collaborator-generated domain name, or by attempting to load remote classes from the domain name into a Java application. Freddy checks for new Collaborator issues every 60 seconds and marks them in the issues list with `RCE (Collaborator)`.

## Supported Targets ##
The following targets are currently supported (italics are new in v2.0):

**Java**

- *BlazeDS AMF 0 (detection, RCE)*
- *BlazeDS AMF 3 (detection, RCE)*
- *BlazeDS AMF X (detection, RCE)*
- *Burlap (detection, RCE)*
- *Castor (detection, RCE)*
- FlexJson (detection)
- Genson (detection)
- *Hessian (detection, RCE)*
- Jackson (detection, RCE)
- JSON-IO (detection, *RCE*)
- JYAML (detection, RCE)
- *Kryo (detection, RCE)*
- *Kryo using StdInstantiatorStrategy (detection, RCE)*
- *ObjectInputStream (detection, RCE)*
- *Red5 AMF 0 (detection, RCE)*
- *Red5 AMF 3 (detection, RCE)*
- *SnakeYAML (detection, RCE)*
- *XStream (detection, RCE)*
- *XmlDecoder (detection, RCE)*
- *YAMLBeans (detection, RCE)*

**.NET**

- *BinaryFormatter (detection, RCE)*
- *DataContractSerializer (detection, RCE)*
- DataContractJsonSerializer (detection, RCE)
- FastJson (detection, RCE)
- FsPickler JSON support (detection)
- FsPickler XML support (detection)
- JavascriptSerializer (detection, RCE)
- Json.Net (detection, RCE)
- *LosFormatter (detection, RCE) - Note not a module itself, supported through ObjectStateFormatter*
- *NetDataContractSerializer (detection, RCE)*
- *ObjectStateFormatter (detection, RCE)*
- *SoapFormatter (detection, RCE)*
- Sweet.Jayson (detection)
- *XmlSerializer (detection, RCE)*

Released under agpl-3.0, see LICENSE for more information
